# 🔧 HƯỚNG DẪN CẤU HÌNH THU THẬP DATASET - ĐÃ ĐƯỢC TỐI ƯU

**Ngày cập nhật**: 2026-04-17
**Trạng thái**: ✅ Tất cả file đã được điều chỉnh theo topology thực tế

---

## 📊 PHÂN TÍCH TOPOLOGY MẠNG

```
┌─────────────────────────────────────────────────────────────┐
│                    RESEARCH TOPOLOGY                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  BOTNET (10.0.1.x)          NORMAL (10.0.2.x)              │
│  h1-h20                     h60-h65                         │
│    │                           │                            │
│    s4 ─────────────────       s3 ──────────────             │
│      \   (Distribution) /     /   (Distribution)            │
│       \    s2 ─────────────S1──────── s6 ─────────────      │
│         \       /       /         \ (Distribution)  \       │
│                                                     \       │
│  BACKGROUND SERVICES (10.0.0.x) - ❌ PHẢI LOẠI BỎ  │
│  ├─ h70: WebServer (10.0.0.100) → s6 ────────────┘       │
│  ├─ h71: DNS (10.0.0.101) → s5                           │
│  ├─ h72: API (10.0.0.102) → s5                           │
│  ├─ h80: IDS (10.0.0.200) → s5                           │
│  ├─ h81: Honeypot (10.0.0.201) → s5                      │
│  └─ h82: Monitor (10.0.0.202) → s6                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Traffic Path:**
- **Botnet** → s4 → s2 → s1 → s6 → Proxy (Web 10.0.0.100)
- **Normal** → s3 → s1 → s6 → Proxy (Web 10.0.0.100)
- **Monitoring Point**: s6-eth4 (mirror port trên h82)

---

## 🚫 BA LOẠI BACKGROUND TRAFFIC CẦN LỌC

### 1️⃣ **Discovery Traffic (ICMP)**
- **Loại**: Protocol 1 (ICMP Ping)
- **Nguồn**: ONOS learning topology (Phase 1-3)
- **Giải pháp**: ✅ ĐƯỢC LỌC BỞI `batPack123.py` & `batPackSL.py`
  ```python
  if flow.protocol == 1:
      continue  # Bỏ qua ICMP hoàn toàn
  ```

### 2️⃣ **Background Services (10.0.0.x)**
- **Loại**: DNS, API, Web, IDS hoạt động nền
- **IP Range**: `10.0.0.0/24`
- **Giải pháp**: ✅ LỌC BỞI `STRICT_SUBNET_FILTER` trong `auto_dataset_generator.py`
  ```python
  # Chỉ nhận traffic CÓ ÍT NHẤT một endpoint từ dải mục tiêu
  # VÀ PHẢI LỌC BỎ traffic 10.0.0.x ↔ 10.0.0.x (background services)
  if src_ip.startswith("10.0.0.") and dst_ip.startswith("10.0.0."):
      continue  # Loại bỏ background services
  ```

### 3️⃣ **Control Plane Traffic**
- **Loại**: LLDP, ARP, OpenFlow (6633/6653)
- **Giải pháp**: ✅ LỌC BỞI `batPack123.py` & `batPackSL.py`
  ```python
  RESTRICTED_PORTS = {22, 6633, 6653}  # SSH, OpenFlow
  ```

---

## 📝 CẤU HÌNH CÁC FILE HỆ THỐNG

### **File 1: `batPack123.py` (Thu thập Normal + HTTP Flood + SYN Flood + UDP Flood)**

| Tham số | Giá trị | Lý do |
|--------|--------|------|
| `RESTRICTED_PORTS` | `{22, 6633, 6653}` | Loại bỏ SSH (admin), OpenFlow |
| `idle_timeout` | `1` giây | Đủ để bắt traffic ngắn hạn |
| `active_timeout` | `5` giây | Chốt luồng trước khi quá lâu |
| **Lọc ICMP** | ✅ YES | Loại bỏ Ping discovery |
| **Lọc duplicate** | ✅ YES | Chỉ ghi khi có sự thay đổi |

**Các loại attack hỗ trợ:**
- ✅ HTTP Flood (~3-5s, yêu cầu liên tục)
- ✅ SYN Flood (~5-10s, gói tin liên tục)
- ✅ UDP Flood (~5-10s, gói tin liên tục)
- ✅ Normal (~30-60s, request thường xuyên)

---

### **File 2: `batPackSL.py` (Thu thập Slowloris)**

| Tham số | Giá trị | Lý do |
|--------|--------|------|
| `idle_timeout` | `30` giây | ⚠️ **QUAN TRỌNG**: Slowloris giữ kết nối 30-60s, không được timeout quá sớm |
| `active_timeout` | `60` giây | Slowloris kéo dài lâu hơn các attack khác |
| `n_dissections` | `20` | Chi tiết HTTP header (detect keep-alive) |
| **Anomaly_Score (is_weird)** | `duration > 10s AND pkt < 20` | Phát hiện Slowloris: kết nối lâu nhưng ít gói tin |

**Đặc điểm Slowloris:**
- Kết nối TCP lâu (30-60 giây)
- Gửi HTTP request chậm rãi (partial headers)
- Packet rate rất thấp (~0.1 pkt/s)
- Byte rate rất thấp (~50-200 bytes/s)

---

### **File 3: `auto_dataset_generator.py` (Phân loại & Lọc Dataset)**

| Tham số | Giá trị | Lý do |
|--------|--------|------|
| `STRICT_SUBNET_FILTER` | `"1"` (True) | ✅ **BẬT**: Chỉ nhận clean data từ attack/normal |
| `ignore_until` | `2.0` giây | Xả sạch buffer cũ tránh nhiễu |
| `TARGET_SAMPLES_PER_CLASS` | `50,000` | "Số vàng" cho CNN-GRU |
| `CSV_WRITE_BATCH` | `1,000` | Batch ghi CSV (tối ưu I/O) |

**Logic lọc subnet chặt chẽ:**

```
Label 0 (Normal):
├─ ✅ Chấp nhận: Traffic CÓ ÍT NHẤT src/dst từ 10.0.2.x
├─ ❌ Loại bỏ: Traffic 10.0.0.x ↔ 10.0.0.x (background services)
├─ ❌ Loại bỏ: Traffic không chứa 10.0.2.x (noise)

Label 1-4 (Attack):
├─ ✅ Chấp nhận: Traffic CÓ ÍT NHẤT src/dst từ 10.0.1.x
├─ ❌ Loại bỏ: Traffic 10.0.0.x ↔ 10.0.0.x (background services)
├─ ❌ Loại bỏ: Traffic không chứa 10.0.1.x (noise)
```

**5 Nhãn (Labels):**
```
0: Normal       (Clients 10.0.2.x request bình thường)
1: UDP Flood    (Botnet 10.0.1.x → UDP 10.0.0.100)
2: SYN Flood    (Botnet 10.0.1.x → TCP SYN 10.0.0.100:80)
3: HTTP Flood   (Botnet 10.0.1.x → HTTP GET 10.0.0.100:80)
4: Slowloris    (Botnet 10.0.1.x → Slow HTTP 10.0.0.100:80)
```

---

## 🎯 CHỈ ĐẠO CHẠY THỬ NGHIỆM

### **Scenario 1: Thu thập Normal Traffic (50k samples)**

```bash
# Terminal 1: Bắt đầu phát hiện & ghi dữ liệu
cd /home/tgf/Documents/DoAn_SDN
sudo python3 thuThapData/auto_dataset_generator.py

# Terminal 2 (Mininet): Khởi động normal clients
py [net.get(f'h{i}').cmd('python3 traffic/normal.py https://10.0.0.100 &') for i in range(60, 65)]
```

**Output mong đợi:**
```
[GENERATOR] Đang thu thập dữ liệu cho: Normal
   [Đang quét] Tiến độ: 15,234/50,000 | raw=18,920 dup=1,200 invalid=45 drop_subnet=2,441
   ✅ Xong! Đã thu thập 50,000 mẫu cho Normal
```

**Giải thích các bộ đếm:**
- `raw=18,920`: 18,920 flow được NFStreamer phát hiện
- `dup=1,200`: 1,200 duplicate (cùng features, loại bỏ)
- `invalid=45`: 45 flow missing features (< 13 features)
- `drop_subnet=2,441`: 2,441 bị drop vì không từ 10.0.2.x hoặc là background (10.0.0.x ↔ 10.0.0.x)
- **Kết quả**: 15,234 mẫu sạch được ghi vào CSV

---

### **Scenario 2: Thu thập HTTP Flood (50k samples)**

```bash
# Terminal 1: Bắt đầu phát hiện & ghi dữ liệu
cd /home/tgf/Documents/DoAn_SDN
sudo python3 thuThapData/auto_dataset_generator.py

# Terminal 2 (Mininet): Khởi động HTTP Flood attack
py [net.get(f'h{i}').cmd('python3 attack/http_flood.py https://10.0.0.100 &') for i in range(1, 5)]
```

---

### **Scenario 3: Thu thập Slowloris (50k samples)**

```bash
# Terminal 1: Chạy batPackSL.py (timeout khác)
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 batPackSL.py

# Terminal 2: Chạy generator
sudo python3 auto_dataset_generator.py

# Terminal 3 (Mininet): Khởi động Slowloris attack
py [net.get(f'h{i}').cmd('python3 attack/slowloris.py https://10.0.0.100 &') for i in range(1, 5)]
```

---

## 📈 CHỈ TIÊU CHẤT LƯỢNG DATASET

| Chỉ tiêu | Giá trị | Mục tiêu |
|---------|--------|---------|
| **Số mẫu/nhãn** | 50,000 | Đủ cho CNN-GRU học tốt |
| **Tỷ lệ lọc subnet** | < 10% | Tránh quá lạo cạn |
| **Tỷ lệ duplicate** | < 5% | Dataset đa dạng |
| **Tỷ lệ invalid** | < 1% | Dữ liệu sạch |
| **Thời gian thu thập** | 20-40 phút/nhãn | Hợp lý cho test |

---

## ⚙️ CẤU HÌNH NÂNG CAO (Tuning)

### **Tắt Subnet Filter (nếu traffic không đủ):**
```bash
STRICT_SUBNET_FILTER=0 sudo python3 auto_dataset_generator.py
```

### **Cắt giảm threshold timeout (thu thập nhanh hơn):**
Sửa trong `batPackSL.py`:
```python
idle_timeout=15,        # Giảm từ 30
active_timeout=30,      # Giảm từ 60
```

### **Tăng batch ghi (tối ưu I/O):**
Sửa trong `auto_dataset_generator.py`:
```python
CSV_WRITE_BATCH = 2000  # Tăng từ 1000
```

---

## ✅ CHECKLIST TRƯỚC KHI THU THẬP

- [ ] Mininet topology đã khởi động (`sudo python3 system.py` → containernet>)
- [ ] Xác nhận monitor port đúng: `s6-eth4` hoặc `h82-eth1`
- [ ] Xác nhận network IPs:
  - Normal clients: `10.0.2.60-65` (`h60-h65`)
  - Botnet: `10.0.1.1-20` (`h1-h20`)
  - Proxy/Web: `10.0.0.100` (`h70`)
- [ ] Chạy `sudo python3 thuThapData/auto_dataset_generator.py` TRƯỚC
- [ ] Copy lệnh traffic từ script → paste vào Mininet
- [ ] Xem tiến độ tăng ≥ 50 samples/giây

---

## 🐛 TROUBLESHOOTING

### **Q: Tiến độ 0/50,000 mãi không tăng?**
**A:** Kiểm tra:
1. Traffic script đã chạy trên Mininet? (`py net.get('h60').cmd(...)`)
2. Monitor interface đúng? (`ss6-eth4` hoặc `h82-eth1`)
3. Subprocess batPack đã tạo FIFO? (xem log)

### **Q: drop_subnet quá cao (> 50%)?**
**A:** Topology IP sai, disable subnet filter:
```bash
STRICT_SUBNET_FILTER=0 sudo python3 auto_dataset_generator.py
```

### **Q: dup quá cao (> 20%)?**
**A:** Tăng delay giữa request:
```python
# Sửa traffic/*.py:
time.sleep(random.uniform(0.5, 2.0))  # Tăng từ 0.2-1.0
```

---

## 📚 THAM KHẢO

- **NFStreamer docs**: https://nfstream.org/docs/
- **Features (13 columns)**: `config.py` → `FEATURES_NAMES`
- **Attack thông số**: Xem `attack/*.py`

**Sửa lần cuối**: 2026-04-17
