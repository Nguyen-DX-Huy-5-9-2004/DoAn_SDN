import requests
import random
import time
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

target = sys.argv[1] if len(sys.argv) > 1 else "https://10.0.0.10"

# Danh sách User-Agents thực tế
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

# Các đường dẫn thực tế trên Web1
PATHS = [
    "/",
    "/accounts/login/",
    "/api/system_status",
    "/static/index.html",
    "/favicon.ico"
]

print(f"[NORMAL TRAFFIC] Bắt đầu mô phỏng người dùng thật tới {target}...")

while True:
    try:
        # Chọn ngẫu nhiên User-Agent và Path
        ua = random.choice(USER_AGENTS)
        path = random.choice(PATHS)
        url = f"{target.rstrip('/')}{path}"
        
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"
        }

        # Mô phỏng cả GET và thỉnh thoảng POST (như đang đăng nhập)
        if path == "/accounts/login/" and random.random() > 0.7:
            data = {"username": "user1", "password": "password123"}
            requests.post(url, headers=headers, data=data, verify=False, timeout=5)
        else:
            requests.get(url, headers=headers, verify=False, timeout=5)
            
    except Exception:
        pass

    # "Think time" - Thời gian người dùng đọc nội dung (3-8 giây)
    time.sleep(random.uniform(3.0, 8.0))