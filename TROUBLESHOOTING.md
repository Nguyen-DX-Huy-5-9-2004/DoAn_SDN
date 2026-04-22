# 🔧 TROUBLESHOOTING: TẠI SAO TRAFFIC KHÔNG TĂNG?

**Trạng thái hiện tại**: Traffic từ `10.0.0.10 ↔ 10.0.0.11` (background services), không phải từ clients (10.0.2.x)

---

## 🎯 ROOT CAUSE (Nguyên nhân gốc rễ)

**Lệnh Mininet chưa chạy đúng hoặc không chạy:**
```
py [net.get(f'h{i}').cmd('python3 traffic/normal.py https://10.0.0.10 &') for i in range(60, 65)]
```

**Hoặc**: Network routing sai, h60-h65 không kết nối được đến 10.0.0.10.

---

## 📋 BƯỚC 1: Debug xem Traffic từ đâu

### Terminal 1 (Thu thập):
```bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 batPack123.py
```

### Terminal 2 (Debug):
```bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData
python3 debug_traffic.py
```

**Output sẽ cho bạn biết:**
```
📊 THỐNG KÊ IP SOURCES:
  10.0.0.10            :  20 lần  (❌ Background - SAI!)
  10.0.2.60            :   0 lần  (✅ Normal - PHẢI CÓ)
  10.0.1.5             :   0 lần  (✅ Attack - PHẢI CÓ)

❌ VẤN ĐỀ: Traffic chỉ từ background services!
   → Lệnh Mininet không chạy đúng hoặc network routing sai
```

---

## 📋 BƯỚC 2: Kiểm tra Mininet Terminal

### Trong Mininet:

**2a. Liệt kê toàn bộ hosts:**
```
containernet> hosts
```

Kết quả mong đợi:
```
h1 h2 ... h20 h60 h61 h62 h63 h64 h65 h70 h71 h72 h80 h81 h82 web1 db1
```

❌ **Nếu thiếu h60-h65**: Topology không được khởi động đúng! Chạy lại `system.py`

---

**2b. Kiểm tra xem h60 có chạy được không:**
```
containernet> h60 echo "Test"
```

Kết quả mong đợi:
```
Test
```

❌ **Nếu không có output**: h60 chưa khởi tạo!

---

**2c. Kiểm tra IP của h60:**
```
containernet> h60 ip addr show
```

Kết quả mong đợi:
```
inet 10.0.2.60/24 brd 10.0.2.255 scope global eth0
```

❌ **Nếu khác (ví dụ 10.0.0.x)**: Topology sai! Kiểm tra `research_topo.py`

---

## 📋 BƯỚC 3: Test Network Routing

### Trong Mininet:

**3a. Ping từ h60 tới Web1:**
```
containernet> h60 ping -c 4 10.0.0.10
```

Kết quả mong đợi:
```
PING 10.0.0.10 (10.0.0.10) 56(84) bytes of data.
64 bytes from 10.0.0.10: icmp_seq=1 ttl=64 time=2.45 ms
...
4 packets transmitted, 4 received, 0% packet loss
```

❌ **Nếu `100% packet loss`**: Network không kết nối! Kiểm tra switch/link

---

**3b. Curl từ h60 tới Web1 (HTTP):**
```
containernet> h60 curl -v http://10.0.0.10:8000
```

Kết quả mong đợi:
```
Connected to 10.0.0.10 (10.0.0.10) port 8000
< HTTP/1.1 200 OK
```

❌ **Nếu `Connection refused` hoặc timeout**: Web1 chưa chạy!

---

## 📋 BƯỚC 4: Chạy Manual Test

### Terminal Mininet:

**Chạy lệnh traffic này từng bước:**

```bash
# Step 1: Chạy trên h60 một lần để test
containernet> h60 python3 traffic/normal.py http://10.0.0.10:8000 &

# Step 2: Xem output
containernet> 
[NORMAL TRAFFIC] Host h60 (PID 1234) bắt đầu truy cập http://10.0.0.10:8000...
[NORMAL h60] Success: 5, Fail: 0  <-- Phải thấy dòng này!
```

✅ **Nếu thấy "Success: X"**: Traffic đang được tạo!

---

## 📋 BƯỚC 5: Chạy Batch Traffic

**Sau khi test xong 1 host, chạy tất cả:**

```bash
containernet> py [net.get(f'h{i}').cmd('python3 traffic/normal.py http://10.0.0.10:8000 &') for i in range(60, 65)]
```

**Sau 5 giây, check debug script:**

```bash
Terminal 2: python3 debug_traffic.py
```

Kết quả mong đợi:
```
📊 THỐNG KÊ IP SOURCES:
  10.0.2.60            :  15 lần  ✅ TỐTLÀNH!
  10.0.2.61            :  18 lần  ✅ TỐTLÀNH!
  10.0.2.62            :  12 lần  ✅ TỐTLÀNH!
  ...
```

---

## 🛠️ CÁC CẢM BIẾN KHÁC

### **Vấn đề 1: Web1 chưa chạy Django**

**Triệu chứng**: Curl trả về `Connection refused` hoặc `502 Bad Gateway`

**Giải pháp:**
```bash
# Trong Mininet
containernet> web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:80 > /tmp/django.log 2>&1 &'

# Sau 5s, test lại:
containernet> h60 curl -s http://10.0.0.10 | head -20
```

---

### **Vấn đề 2: Interface sai**

**Triệu chứng**: `batPack123.py` chọn `s6-eth4` nhưng không nhận traffic

**Giải pháp**: Thử interface khác:
```bash
BATPACK_IFACE=h82-eth1 sudo python3 batPack123.py
# Hoặc:
BATPACK_IFACE=s3-eth4 sudo python3 batPack123.py
```

---

### **Vấn đề 3: FIFO bị khoá**

**Triệu chứng**: Generator chạy nhưng `batPack` không phát sinh dữ liệu

**Giải pháp**:
```bash
# Xóa FIFO cũ:
sudo rm -f zeek_stream.json

# Chạy lại batPack:
sudo python3 batPack123.py
```

---

## ✅ QUICK FIX (Nếu vẫn không được)

Hãy chạy toàn bộ hệ thống từ đầu:

```bash
# Terminal 1: Bắt đầu hệ thống
cd ~/Documents/DoAn_SDN
./start.sh
# Khi thấy "containernet>" → bước tiếp theo

# Terminal 2: Start Mininet topology
cd ~/Documents/DoAn_SDN
containernet> help
containernet> nodes
containernet> links

# Terminal 3: Start batPack
cd ~/Documents/DoAn_SDN/thuThapData
sudo python3 batPack123.py

# Terminal 4: Start generator
cd ~/Documents/DoAn_SDN/thuThapData
sudo python3 auto_dataset_generator.py

# Terminal 5 (sau 3s): Chạy Normal Traffic
containernet> py [net.get(f'h{i}').cmd('python3 traffic/normal.py http://10.0.0.10:8000 &') for i in range(60, 65)]
```

**Xem kết quả:**
```
Terminal 4 (Generator):
   [Đang quét] Tiến độ: 50/50,000 | raw=200 dup=5 invalid=0 drop_subnet=0 ✅
```

---

## 📞 Nếu vẫn không được?

1. Gửi output của `debug_traffic.py`
2. Gửi output của `batPack123.py`
3. Gửi `docker ps` (kiểm tra web1, db1 có chạy không)
4. Gửi output `containernet> nodes` và `links`

