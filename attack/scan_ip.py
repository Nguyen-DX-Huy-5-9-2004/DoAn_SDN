import requests
import urllib3
import re

# Tắt cảnh báo bảo mật khi dùng verify=False (do ta truy cập thẳng vào IP nên SSL sẽ báo lỗi)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Danh sách các "nghi phạm"
ips = [
    "101.96.125.163", "101.96.125.164", "101.96.125.165", 
    "101.96.125.167", "101.96.125.168", "101.96.125.169", 
    "101.96.125.173", "101.96.125.174", "101.96.125.175", 
    "101.96.125.176", "101.96.125.177", "101.96.125.178", 
    "101.96.125.179", "101.96.125.180"
]

domain = "sinhvien.uneti.edu.vn"
headers = {"Host": domain}

print(f"BẮT ĐẦU QUÉT TÌM MÁY CHỦ GỐC CỦA {domain}...\n" + "="*50)

for ip in ips:
    for protocol in ["http", "https"]:
        url = f"{protocol}://{ip}"
        try:
            # Gửi request với Host header giả mạo, timeout 5 giây để tránh bị treo
            response = requests.get(url, headers=headers, verify=False, timeout=5)
            
            # Trích xuất thẻ <title> của trang web để xem nó là trang gì
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else "Không tìm thấy tiêu đề"
            
            print(f"[*] Thử {url:<25} | Status: {response.status_code} | Tiêu đề: {title}")
            
            # Nếu trong nội dung có chữ Uneti hoặc Kinh tế, báo động ngay
            if "uneti" in response.text.lower() or "sinh viên" in response.text.lower():
                print(f"    => BINGO!!! RẤT CÓ THỂ ĐÂY LÀ MÁY CHỦ GỐC: {ip} ({protocol})\n")
                
        except requests.exceptions.RequestException:
            print(f"[*] Thử {url:<25} | Lỗi: Không thể kết nối hoặc Timeout")

print("="*50 + "\nHOÀN THÀNH QUÉT!")