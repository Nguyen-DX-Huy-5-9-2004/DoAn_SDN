# 🖥️ HƯỚNG DẪN SETUP 3 TERMINALS - Dataset Generation

**Ngày:** April 17, 2026  
**Mục tiêu:** Setup đúng thứ tự 3 terminals để tránh lỗi FIFO conflict

---

## ⚠️ QUAN TRỌNG: THỨ TỰ KHỞI ĐỘNG

```
Terminal 1: Mininet
   ↓
Terminal 3: batPack123.py (batPack123 phải chạy TRƯỚC Generator!)
   ↓
Terminal 2: auto_dataset_generator.py (Generator)
```

**NHỚ:** Terminal 3 phải chạy trước Terminal 2!

---

## 📋 CHI TIẾT TỪNG TERMINAL

### **TERMINAL 1: Mininet (Khởi động ngay)**

```bash
cd /home/tgf/Documents/DoAn_SDN
source sdn_env/bin/activate
python system.py
```

**Chờ cho đến khi:**
```
mininet>
```

**Output dự kiến:**
```
[*] Starting Mininet research topology...
[*] Creating switches...
[*] Adding hosts...
[*] Starting Docker containers...
[*] Connecting to ONOS controller...
mininet> (ready for commands)
```

**Để mở thêm terminals, bạn sẽ giữ Terminal này LUÔN CHẠY**

---

### **TERMINAL 3: Network Flow Collector (Khởi động TRƯỚC Terminal 2!)**

**MỤC ĐÍC:** Bắt traffic network từ Interface s6-eth5

**Lệnh:**
```bash
# 1. Đi vào thư mục
cd /home/tgf/Documents/DoAn_SDN/thuThapData

# 2. Activate environment
source ../sdn_env/bin/activate

# 3. Chạy batPack123 (cho labels 0, 1, 2, 3: Normal, UDP, SYN, HTTP)
sudo python3 batPack123.py
```

**Output dự kiến:**
```
[BATPACK] Đã tạo Named Pipe: zeek_stream.json
[BATPACK] Interface chọn: s6-eth5
[BATPACK] Bắt đầu thu thập trên s6-eth5...
```

**⚠️ LƯU Ý:**
- **KHÔNG nhấn Ctrl+C!** Giữ Terminal 3 chạy mãi
- Chỉ dừng khi `collect_data(0,1,2,3)` hoàn thành
- Khi Generator yêu cầu collect Slowloris (label 4):
  - Nhấn Ctrl+C để dừng batPack123.py
  - Chạy batPackSL.py thay thế (xem bước dưới)

**Để kiểm tra batPack hoạt động:**
```bash
# Terminal mới (Terminal 3b):
ls -la thuThapData/zeek_stream.json
# Phải thấy file hiện diện

# Hoặc kiểm tra kích thước:
watch -n 1 'wc -l thuThapData/zeek_stream.json'
# Kích thước phải tăng liên tục
```

---

### **TERMINAL 2: Data Generator (Khởi động SAU Terminal 3)**

**MỤC ĐÍC:** Orchestrate việc chạy attacks và thu thập dữ liệu

**Lệnh:**
```bash
# 1. Đi vào thư mục
cd /home/tgf/Documents/DoAn_SDN/thuThapData

# 2. Activate environment
source ../sdn_env/bin/activate

# 3. Chạy generator
sudo python3 auto_dataset_generator.py
```

**Output dự kiến:**
```
======================================================================
🚀 QUY TRÌNH THU THẬP DATASET PHÂN LOẠI CHI TIẾT (5 NHÃN)
======================================================================

👉 BƯỚC: BẬT TRAFFIC BÌNH THƯỜNG
======================================================================
[1] Hãy COPY lệnh dưới đây và DÁN vào Terminal Mininet (mininet>):
\033[92mpy [net.get(f'h{i}').cmd('python3 traffic/normal.py http://10.0.0.10:8000 &') for i in range(60, 65)]\033[0m
----------------------------------------------------------------------
[2] Sau khi gõ xong bên Mininet, HÃY BẤM ENTER TẠI ĐÂY ĐỂ TIẾP TỤC...
```

**Flow:**
1. Generator báo một bước (ví dụ: "BẬT TRAFFIC BÌNH THƯỜNG")
2. Bạn copy lệnh (in màu xanh) 
3. Dán vào Terminal 1 (Mininet prompt)
4. Nhấn Enter để chạy lệnh ở Mininet
5. Quay lại Terminal 2, nhấn ENTER
6. Generator bắt đầu thu thập dữ liệu
7. Lặp lại cho bước tiếp theo

**Các bước sẽ chạy:**
1. Normal Traffic → collect_data(0) → Dừng
2. UDP Flood → collect_data(1) → Dừng
3. SYN Flood → collect_data(2) → Dừng
4. HTTP Flood (Hash) → collect_data(3, half) → Dừng
5. HTTP Flood (JSON) → collect_data(3, half) → Dừng
6. **SWITCH TO Terminal 3b:** Dừng batPack123, chạy batPackSL.py
7. Slowloris → collect_data(4) → Dừng

---

## 📊 TIMELINE CHI TIẾT

```
Time: 0s
├─ Terminal 1: python system.py
│  └─ Chờ 5-10s cho mininet> prompt
│
├─ Terminal 3: sudo python3 batPack123.py
│  └─ Chờ 3-5s cho "[BATPACK] Bắt đầu thu thập..." message
│
└─ Terminal 2: sudo python3 auto_dataset_generator.py
   ├─ Nhấn ENTER khi thấy lệnh (copy vào Terminal 1)
   ├─ Chờ Normal traffic: ~5-8 phút
   │
   ├─ Nhấn ENTER khi thấy lệnh UDP Flood
   ├─ Chờ UDP thu thập: ~3-5 phút
   │
   ├─ Nhấn ENTER khi thấy lệnh SYN Flood
   ├─ Chờ SYN thu thập: ~3-5 phút
   │
   ├─ Nhấn ENTER khi thấy lệnh HTTP Flood (Hash)
   ├─ Chờ HTTP(Hash) thu thập: ~3-5 phút
   │
   ├─ Nhấn ENTER khi thấy lệnh HTTP Flood (JSON)
   ├─ Chờ HTTP(JSON) thu thập: ~3-5 phút
   │
   ├─ [**CHUYỂN Terminal 3: Dừng batPack123, chạy batPackSL.py**]
   │  └─ Chờ "[BATPACK] Đã tạo Named Pipe: zeek_stream_slowloris.json"
   │
   ├─ Nhấn ENTER khi thấy lệnh Slowloris
   ├─ Chờ Slowloris thu thập: ~5-8 phút
   │
   └─ Generator hoàn thành
      └─ Thấy "🎉 THÀNH CÔNG! Dataset 5 lớp..."

TỔNG: ~35-50 phút
```

---

## 🔄 QUẢN LÝ 3 TERMINALS

### Cách mở Terminal mới trong Linux

**Option 1: Tab Terminal (nếu dùng terminal GUI)**
```bash
Ctrl + Tab  # Mở tab mới
Ctrl + N    # Hoặc: mở cửa sổ mới
```

**Option 2: tmux (Tối ưu nhất)**
```bash
# Terminal 0 (chính)
tmux new-session -s main
# Đang ở trong tmux session "main"

# Mở Terminal 1 (Mininet) - trong cùng session
tmux new-window -t main -n "mininet"
# Chạy: python system.py

# Mở Terminal 2 (Generator) - trong cùng session
tmux new-window -t main -n "generator"
# Chạy: sudo python3 auto_dataset_generator.py

# Mở Terminal 3 (batPack) - trong cùng session
tmux new-window -t main -n "batpack"
# Chạy: sudo python3 batPack123.py

# Chuyển giữa terminals:
Ctrl + b, n   # Qua terminal tiếp theo
Ctrl + b, p   # Qua terminal trước
Ctrl + b, 0   # Terminal 0
Ctrl + b, 1   # Terminal 1
...etc
```

**Option 3: GNU Screen**
```bash
screen -S main
# Mở các windows tương tự như tmux
```

---

## ⚠️ LỖI THƯỜNG GẶP & GIẢI PHÁP

### Lỗi 1: "batPack123.py không tạo FIFO"
**Nguyên nhân:** Terminal 3 không chạy trước Terminal 2

**Giải pháp:**
```bash
# Terminal 2 sẽ báo:
[GENERATOR] Đang đợi batPack.py tạo Named Pipe: zeek_stream.json...

# Ctrl+C tại Terminal 2
# Chạy Terminal 3: batPack123.py
# Đợi khi thấy: [BATPACK] Bắt đầu thu thập...
# RỒIZỚI chạy lại Terminal 2
```

### Lỗi 2: "zeek_stream.json: Permission denied"
**Nguyên nhân:** Không chạy với sudo

**Giải pháp:**
```bash
# Hãy dùng: sudo python3 auto_dataset_generator.py
# KHÔNG: python3 auto_dataset_generator.py
```

### Lỗi 3: "NFStreamer timeout" ở batPack
**Nguyên nhân:** Network không có traffic hoặc interface sai

**Giải pháp:**
```bash
# Check interface
ip link show | grep s6-eth

# Nếu không tìm được s6-eth5, hãy sửa IFACE trong batPack123.py
# Hoặc set environment:
export BATPACK_IFACE="s6-eth4"
sudo python3 batPack123.py
```

### Lỗi 4: "Slowloris phase không find zeek_stream_slowloris.json"
**Nguyên nhân:** Quên switch sang batPackSL.py

**Giải pháp:**
```bash
# Terminal 2 sẽ báo:
[GENERATOR] Đang đợi batPack.py tạo Named Pipe: zeek_stream_slowloris.json...

# Terminal 3: Dừng batPack123.py (Ctrl+C)
# Terminal 3: Chạy:
sudo python3 batPackSL.py

# Đợi khi thấy: [BATPACK] Đã tạo Named Pipe: zeek_stream_slowloris.json
# Sau đó, Terminal 2 sẽ tự động tiếp tục
```

---

## ✅ CHECKLIST KHỞI ĐỘNG

- [ ] Terminal 1: Mininet running (mininet> prompt visible)
- [ ] Terminal 3: batPack123.py running ("[BATPACK] Bắt đầu thu thập...")
- [ ] Terminal 2: auto_dataset_generator.py running (prompt waiting for first step)
- [ ] Normal traffic: Thực hiện bước 1 (5-8 phút)
- [ ] UDP Flood: Thực hiện bước 2 (3-5 phút)
- [ ] SYN Flood: Thực hiện bước 3 (3-5 phút)
- [ ] HTTP Flood (Hash + JSON): Thực hiện bước 4 (3-5 phút)
- [ ] Switch batPack123 → batPackSL.py (Terminal 3)
- [ ] Slowloris: Thực hiện bước 5 (5-8 phút)
- [ ] ✅ Dataset v6 ready: master_dataset_v6.csv

---

## 🎯 RECAP

**Terminal 1:** Mininet
- Khởi động ngay
- Giữ chạy mãi
- Copy/paste các lệnh khi Terminal 2 báo

**Terminal 3:** batPack123 → batPackSL (Khởi động TRƯỚC Terminal 2!)
- Chạy batPack123.py đầu tiên
- Sau khi collect(0,1,2,3) xong, dừng & chạy batPackSL.py

**Terminal 2:** Generator (Khởi động cuối)
- Orchestrate toàn bộ quy trình
- Chờ input từ user (nhấn ENTER giữa các bước)

---

**Bắt đầu ngay! 🚀**

