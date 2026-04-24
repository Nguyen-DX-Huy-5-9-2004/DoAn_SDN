import requests
import random
import time
import urllib3
import sys
import socket 
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)# Tắt cảnh báo SSL cho môi trường Lab

# Support cả HTTP và HTTPS
target = sys.argv[1] if len(sys.argv) > 1 else "http://10.0.0.10"
if not target.startswith('http://') and not target.startswith('https://'):
    target = f"http://{target}:8000"

print(f"[NORMAL TRAFFIC] Host {socket.gethostname()} (PID {os.getpid()}) bắt đầu truy cập {target}...")





# Danh sách User-Agents thực tế
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0"
]

# Các đường dẫn thực tế trên Web1
# TỐI ƯU: Chia thành FAST paths (lightweight, ~200-400ms) và MEDIUM paths (~800ms-1.5s)

# FAST paths - gọi thường xuyên (70% requests) - JSON API & simple pages
FAST_PATHS = [
    "/",
    "/favicon.ico",
    "/api/v1/metrics",
    "/api/system_status"
]

# MEDIUM paths - gọi đôi khi (30% requests) - HTML pages
MEDIUM_PATHS = [
    "/static/index.html",
    "/about/",
    "/search/?q=network+security",
    "/contact/",
    "/accounts/login/"
]

# SKIP protected paths (dashboard, profile, settings) - trả 403 làm chậm quá trình!

session = requests.Session()
session.verify = False

# Retry counter
fail_count = 0
success_count = 0

while True:
    try:
        # Chọn ngẫu nhiên User-Agent cho session
        ua = random.choice(USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "Referer": target,
            "Connection": "close"  # BUỘC server đóng kết nối sau mỗi request
        }
        
        # Mở session mới cho mỗi phiên (tránh Keep-Alive kéo dài gây nhiễu pattern)
        with requests.Session() as s:
            s.verify = False
            s.headers.update(headers)

            # TỐI ƯU: Giảm requests từ 3-10 → 2-5 (nhanh hơn, nhưng vẫn realistic)
            num_requests = random.randint(2, 5)
            for _ in range(num_requests):
                # Biased random: 70% FAST paths, 30% MEDIUM paths
                if random.random() < 0.7:
                    path = random.choice(FAST_PATHS)
                else:
                    path = random.choice(MEDIUM_PATHS)
                
                url = f"{target.rstrip('/')}{path}"
                
                # Mô phỏng cả GET và thỉnh thoảng POST (như đang đăng nhập)
                if path == "/accounts/login/" and random.random() > 0.5:
                    try:
                        data = {"username": f"user_{random.randint(1,100)}", "password": "password123"}
                        s.post(url, data=data, timeout=5)
                        success_count += 1
                    except Exception as e:
                        fail_count += 1
                else:
                    try:
                        r = s.get(url, timeout=5)
                        # Nếu server trả về lỗi 5xx (quá tải) thì cũng nên tính là Fail
                        if r.status_code >= 500:
                            fail_count += 1
                            print(f"[{socket.gethostname()}] Server Error {r.status_code} at {url}")
                        else:
                            success_count += 1
                    except requests.exceptions.Timeout:
                        fail_count += 1
                        print(f"[{socket.gethostname()}] Timeout khi gọi {url}")
                    except requests.exceptions.ConnectionError:
                        fail_count += 1
                        print(f"[{socket.gethostname()}] Connection Refused/Rớt mạng khi gọi {url}")
                    except Exception as e:
                        fail_count += 1
                        print(f"[{socket.gethostname()}] Lỗi khác: {e}")
                
                # Sleep ngẫu nhiên giữa các request trong cùng session (Mô phỏng user đọc web)
                time.sleep(random.uniform(0.5, 2.0))
            
    except requests.exceptions.ConnectionError as e:
        # Server might be starting or overloaded, wait longer to avoid "failed connection" traffic patterns
        print(f"[{socket.gethostname()}] ⚠️ Server unreachable: {e}. Retrying in 5s...")
        time.sleep(5)
    except Exception as e:
        # Server might be starting or overloaded, wait longer to avoid "failed connection" traffic patterns
        print(f"[{socket.gethostname()}] ⚠️ Server unreachable: {e}. Retrying in 5s...")
        time.sleep(5)

    # "Think time" giữa các phiên làm việc (1.0 - 2.0 giây) - Tăng tần suất
    # Vừa đủ nhanh để thu data, vừa đủ chậm để AI thấy sự khác biệt với Flood
    time.sleep(random.uniform(0.2, 0.5))
    
    # In ra progress mỗi 10 phiên
    if (success_count + fail_count) % 10 == 0:
        print(f"[NORMAL {socket.gethostname()}] Success: {success_count}, Fail: {fail_count}")
