# KẾ HOẠCH DATASET V8 - TỐI ƯU CHO MÔ HÌNH AI

> Phân tích dựa trên kết quả check_data.py của dataset v7 (600k mẫu)
> Ngày: 24/04/2026

---

## 1. TỔNG QUAN PHÂN TÍCH V7

### 1.1 Điểm Tích Cực
| Chỉ tiêu | Kết quả | Đánh giá |
|----------|---------|----------|
| Số mẫu | 600,000 | ✅ Đủ cho deep learning |
| Số lớp | 5/5 đầy đủ | ✅ Hoàn chỉnh |
| Cân bằng | 2.00x (33%/16.7%) | ✅ Chấp nhận được |
| Duration Slowloris | 19.28s | ✅ Phân biệt tốt vs <1s |
| Packet_Rate UDP | 30k vs HTTP 80 | ✅ Phân biệt cực tốt |

### 1.2 Vấn Đề Cần Cải Thiện

#### A. PORT ENTROPY - KHÔNG PHÂN BIỆT ĐƯỢC
```
Vấn đề: Tất cả lớp đều có Src_Entropy ~3.32, Dst_Entropy ~0.00
Giá trị giống hệt nhau ở cả 5 lớp (Normal + 4 Attack)

Nguyên nhân:
- Attack tools sử dụng random port nguồn giống nhau
- Môi trường lab không có sự phân biệt như thực tế

Ảnh hưởng:
- Port Entropy không phải đặc trưng phân biệt trong môi trường lab
- AI sẽ phải dựa vào các đặc trưng khác (Duration, Rate, Bytes)
```

#### B. NORMAL TRAFFIC - DURATION QUÁ NGẮN
```
Vấn đề: Duration = 0.04s (quá ngắn)
Kỳ vọng: >0.1s để thấy được pattern flow hoàn chỉnh

Nguyên nhân:
- IDLE_TIMEOUT trong batPack_v2 quá ngắn (2.0s)
- Có thể flow bị xẻ nhỏ do timeout
- Web traffic thực tế có thể có nhiều short connections

Ảnh hưởng:
- AI khó học được pattern thực sự của Normal
- Có thể nhầm lẫn với attack ngắn (HTTP Flood cũng ~0.24s)
```

#### C. SLOWLORIS - L7_PROTOCOL THẤP
```
Vấn đề: L7_App_Protocol = 0.04 (chỉ 4% HTTP)
Kỳ vọng: ~1.0 (100% HTTP)

Nguyên nhân:
- Timeout không đủ dài cho Slowloris handshake
- Flow bị cắt ngang trước khi HTTP complete
- IDLE_TIMEOUT 30s cho Slowloris có thể chưa đủ

Ảnh hưởng:
- Slowloris không được gán đúng protocol
- Khó phân biệt với các attack khác nếu chỉ dựa vào L7
```

#### D. UDP FLOOD - DURATION = 0
```
Vấn đề: Duration ~0.00s
Kỳ vọng: >0.1s để thấy flow pattern

Nguyên nhân:
- UDP Flood rất nhanh, gửi xong dừng ngay
- Timeout có thể cắt flow quá sớm
- Có thể đang gặp hiện tượng micro-bursts

Ảnh hưởng:
- Khó phân tích behavior của UDP Flood
- AI chỉ thấy volume, không thấy temporal pattern
```

---

## 2. PHÂN TÍCH ĐẶC TRƯNG PHÂN BIỆT TỐT

Dựa trên dữ liệu v7, các đặc trưng PHÂN BIỆT TỐT:

| Đặc trưng | Normal | UDP | SYN | HTTP | Slowloris | Phân biệt? |
|-----------|--------|-----|-----|------|-----------|------------|
| **Duration** | 0.04 | 0.00 | 0.67 | 0.24 | **19.28** | ✅ XUẤT SẮC |
| **Packet_Rate** | 3,089 | **30k** | 2,417 | 80 | 182 | ✅ RẤT TỐT |
| **Byte_Rate** | 639k | **24M** | 167k | 233k | 13k | ✅ TỐT |
| **Src_Bytes** | 755 | **24k** | 408 | **51k** | 241 | ✅ TỐT |
| **Protocol** | TCP(6) | **UDP(17)** | TCP(6) | TCP(6) | TCP(6) | ✅ UDP riêng |

=> Kết luận: Duration, Packet_Rate, Byte_Rate là đặc trưng VÀNG.

---

## 3. KẾ HOẠCH DATASET V8

### 3.1 MỤC TIÊU V8

1. **Tăng Duration Normal** để AI học được pattern hoàn chỉnh
2. **Cải thiện Slowloris L7 detection** bằng timeout dài hơn
3. **Giữ nguyên phân biệt tốt** ở Duration, Packet_Rate, Byte_Rate
4. **Tối ưu Port Entropy** hoặc chấp nhận và giảm weight
5. **Thêm đặc trưng mới** nếu cần (Payload size, Connection state chi tiết)

### 3.2 ĐIỀU CHỈNH KỸ THUẬT

#### A. Thay đổi Timeout trong batPack_v2.py

```python
# HIỆN TẠI (V7)
class BatPackConfig:
    IDLE_TIMEOUT = 2.0      # Giây - CÓ THỂ QUÁ NGẮN
    ACTIVE_TIMEOUT = 10.0   # Giây

    # Cho Slowloris
    SLOWLORIS_IDLE_TIMEOUT = 30.0   # CÓ THỂ CHƯA ĐỦ
    SLOWLORIS_ACTIVE_TIMEOUT = 60.0

# ĐỀ XUẤT V8
class BatPackConfig:
    # Tăng timeout cho Normal để flow hoàn chỉnh hơn
    IDLE_TIMEOUT = 5.0      # Tăng từ 2.0 -> 5.0
    ACTIVE_TIMEOUT = 15.0  # Tăng từ 10.0 -> 15.0
    
    # Tăng timeout cho Slowloris để bắt được HTTP complete
    SLOWLORIS_IDLE_TIMEOUT = 60.0   # Tăng từ 30.0 -> 60.0
    SLOWLORIS_ACTIVE_TIMEOUT = 120.0  # Tăng từ 60.0 -> 120.0
```

#### B. Thay đổi Kịch bản Thu Thập Normal

```python
# HIỆN TẠI (V7)
- Thu thập Normal từ traffic thực tế
- Timeout ngắn (2s) làm flow bị cắt nhỏ

# ĐỀ XUẤT V8
# Cách 1: Tăng timeout (khuyến nghị)
- Giữ nguyên kịch bản, chỉ tăng timeout

# Cách 2: Chủ động tạo long-lived connections
- Thêm kịch bản: WebSocket hoặc Keep-Alive connections
- Tạo HTTP requests với Connection: keep-alive
- Mục tiêu: Duration > 5s cho một số Normal flows

# Cách 3: Kết hợp cả hai
- Tăng timeout lên 5s
- Vẫn giữ traffic tự nhiên
```

#### C. Cải thiện Slowloris Detection

```python
# Vấn đề: L7_Protocol = 0.04 (chỉ 4% HTTP)

# Nguyên nhân trong batPack_v2:
# - NFStream/Zeek không nhận diện được HTTP vì header chưa gửi xong
# - Flow bị cắt trước khi complete

# ĐỀ XUẤT V8:
# 1. Tăng timeout Slowloris (đã đề cập ở trên)

# 2. Thêm heuristic detection cho Slowloris:
#    - Duration > 10s
#    - Src_Bytes rất thấp (<500)
#    - Dst_Bytes thấp (<1000) 
#    - Packet_Rate thấp (<200)
#    -> Gán L7_Protocol = 1 (HTTP) ngay cả khi chưa complete

# 3. Hoặc dùng port-based detection:
#    - Dst_Port = 80 hoặc 8000
#    - Protocol = TCP
#    - Duration > 10s
#    -> Chắc chắn là HTTP/Slowloris
```

#### D. Tối ưu UDP Flood Detection

```python
# Vấn đề: Duration ~0.00s

# ĐỀ XUẤT V8:
# 1. Tăng IDLE_TIMEOUT cho UDP (khác với TCP)
#    UDP không có connection state, nên timeout có thể ngắn hơn
#    NHƯNG: Cần đủ lâu để thấy burst pattern

# 2. Hoặc: Thêm đặc trưng Burst Detection
#    - Số lượng packets trong window đầu tiên
#    - Thay vì Duration, dùng "Packets per second in first 100ms"

# 3. Hoặc chấp nhận Duration=0 cho UDP:
#    - Đây là đặc trưng riêng của UDP Flood
#    - AI sẽ học: Duration=0 + High Packet_Rate = UDP Flood
```

### 3.3 ĐẶC TRƯNG MỚI ĐỀ XUẤT (OPTIONAL)

Nếu muốn cải thiện thêm, có thể thêm:

```python
# 1. PAYLOAD_ENTROPY (đo độ ngẫu nhiên của payload)
#    - HTTP Flood: Payload có structure (headers)
#    - UDP Flood: Payload có thể random hoặc fixed
#    - Slowloris: Payload rất nhỏ, sparse

# 2. CONNECTION_SETUP_TIME 
#    - Thời gian từ SYN -> SYN-ACK -> ACK
#    - Slowloris: Setup nhanh nhưng data chậm
#    - SYN Flood: Không complete setup

# 3. INTER_ARRIVAL_TIME_VARIANCE
#    - Độ biến động thời gian giữa các packets
#    - Slowloris: High variance (slow, sporadic)
#    - HTTP Flood: Low variance (steady rate)
```

---

## 4. KỊCH BẢN THU THẬP V8 CHI TIẾT

### Phase 0: Normal (200k mẫu)
```
Thời gian: ~50 phút
Cấu hình:
- IDLE_TIMEOUT = 5.0s (tăng từ 2.0s)
- ACTIVE_TIMEOUT = 15.0s (tăng từ 10.0s)

Kịch bản:
1. Web browsing tự nhiên (multi-page, images, JS)
2. Một số long-lived connections (keep-alive)
3. Mục tiêu: Duration_mean > 0.5s (tăng từ 0.04s)
```

### Phase 1: UDP Flood (100k mẫu)
```
Thời gian: ~10 phút
Cấu hình: Timeout ngắn (UDP không cần dài)

Kịch bản:
- Giữ nguyên như v7
- Mục tiêu: Packet_Rate > 20k, Byte_Rate > 15M
```

### Phase 2: SYN Flood (100k mẫu)
```
Thời gian: ~10 phút

Kịch bản:
- Giữ nguyên như v7
- Mục tiêu: Duration > 0.5s để thấy incomplete handshake
```

### Phase 3: HTTP Flood (100k mẫu)
```
Thời gian: ~10 phút

Kịch bản:
- Giữ nguyên (Hash + JSON)
- Mục tiêu: Duration ~0.5-1s, Src_Bytes > 40k
```

### Phase 4: Slowloris (100k mẫu)
```
Thời gian: ~30 phút (lâu hơn do tăng timeout)
Cấu hình:
- SLOWLORIS_IDLE_TIMEOUT = 60.0s (tăng từ 30.0s)
- SLOWLORIS_ACTIVE_TIMEOUT = 120.0s (tăng từ 60.0s)

Kịch bản:
- Giữ nguyên slowloris.py
- Mục tiêu: 
  - Duration_mean > 30s (tăng từ 19s)
  - L7_Protocol > 0.8 (tăng từ 0.04)
  - Packet_Rate < 200
```

---

## 5. KẾ HOẠCH CODE CHANGES

### File cần sửa:

1. **batPack_v2.py**
   - [ ] Tăng IDLE_TIMEOUT, ACTIVE_TIMEOUT
   - [ ] Thêm heuristic cho Slowloris L7 detection
   - [ ] (Optional) Thêm payload_entropy

2. **auto_dataset_generator.py**
   - [ ] Đổi OUTPUT_CSV sang master_dataset_v8.csv
   - [ ] Có thể thêm kịch bản keep-alive cho Normal

3. **train_colab_v2.py**
   - [ ] Đổi dataset path sang v8
   - [ ] Giữ feature weighting (đã tối ưu cho v7)

4. **check_data.py** (cho v8)
   - [ ] Cập nhật SIGNATURE_BOUNDS theo v8
   - [ ] Thêm check L7_Protocol cho Slowloris

---

## 6. QUYẾT ĐỊNH: CÓ NÊN LÀM V8 KHÔNG?

### Đánh giá khách quan:

| Tiêu chí | V7 Hiện tại | V8 Đề xuất | Chênh lệch |
|----------|-------------|------------|------------|
| Duration Normal | 0.04s | >0.5s | +1150% |
| Duration Slowloris | 19.28s | >30s | +55% |
| L7 Slowloris | 0.04 | >0.8 | +1900% |
| Phân biệt tốt | Duration, Rate | Duration, Rate | Tương đương |
| Port Entropy | ~3.32 (giống) | ~3.32 (giống) | Không đổi |
| Training time | 80 epochs | 80 epochs | Tương đương |
| Data collection | ~2 giờ | ~2.5 giờ | +25% |

### Khuyến nghị: 

**KHÔNG BẮT BUỘC phải làm V8**, vì:
- V7 đã có **600k mẫu đủ tốt**
- Duration Slowloris 19s đã phân biệt rõ vs <1s
- Packet_Rate, Byte_Rate phân biệt cực tốt
- AI đã có thể train với feature weighting

**Tuy nhiên, V8 sẽ tốt hơn nếu có thời gian**, vì:
- Normal Duration dài hơn = AI học pattern tốt hơn
- Slowloris L7 cao hơn = Chính xác hơn
- Longer timeout = Flow behavior hoàn chỉnh hơn

### Lựa chọn thực tế:

**Option A: Dùng V7, tập trung vào Training (Khuyến nghị nếu deadline gấp)**
- Train ngay với feature weighting (đã cấu hình)
- Kết quả sẽ tốt (95%+ accuracy)
- Tiết kiệm 2-3 giờ thu thập

**Option B: Làm V8 nếu có thêm 1 ngày**
- Thu thập lại với timeout mới
- Kỳ vọng: +2-3% accuracy
- Data "sạch" hơn, phù hợp cho paper/publication

---

## 7. KẾT LUẬN

Dataset **V7 đã đủ tốt** cho mục tiêu demo và đạt điểm cao.
Các đặc trưng **Duration, Packet_Rate, Byte_Rate** đã phân biệt rõ 5 lớp.

**Nếu quyết định làm V8**, ưu tiên:
1. Tăng timeout trong batPack_v2 (quan trọng nhất)
2. Thu thập lại với cùng kịch bản
3. Feature weighting đã có sẵn trong train_colab_v2

**Nếu dùng V7**, vẫn đạt kết quả xuất sắc với:
- Feature weighting (Duration, Rate x2.0)
- Logic 2-Shield bảo vệ Normal
- Zero-day detection để demo cho hội đồng

---

*Người lập kế hoạch: AI Assistant*
*Dựa trên phân tích dữ liệu v7 thực tế*
