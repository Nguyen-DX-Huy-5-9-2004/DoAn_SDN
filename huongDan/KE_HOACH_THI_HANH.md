# 🚀 KẾ HOẠCH THI HÀNH CHI TIẾT - DATASET V6 & TRAINING

**Ngày:** April 17, 2026  
**Mục tiêu:** Tạo Dataset v6 (250K samples, 13 features) → Train → Test  
**Thời gian dự kiến:** 2-3 giờ

---

## 📋 TÌNH TRẠNG HIỆN TẠI

✅ **Có sẵn:**
- Dataset v3: 10K samples (13 features) - quá nhỏ
- Code v2.0: Đã hoàn thành & verified
- Environment: Python 3.x, PyTorch, sklearn, pandas

❌ **Cần làm:**
1. Tạo Dataset v6 (50K/class × 5 classes = 250K samples)
2. Chạy training model (Contrastive AE + Parallel Fusion)
3. Test end-to-end với attack scenarios

---

## 🎯 KẾ HOẠCH 3 GIAI ĐOẠN

### **GIAI ĐOẠN 1: TẠO DATASET V6** (30-45 phút)

#### Bước 1.1: Chuẩn bị Mininet
```bash
# Terminal 1: Khởi động Mininet + ONOS
cd /home/tgf/Documents/DoAn_SDN
python system.py
# Hoặc nếu có run_onos.py:
python run_onos.py

# Chờ tới khi nhìn thấy:
# mininet> (prompt Mininet)
```

**Dấu hiệu thành công:**
- Mininet prompt xuất hiện
- Web1, Web2, DB1 containers đang chạy
- Có thể gõ lệnh như: `mininet> h1 ping h2`

---

#### Bước 1.2a: Khởi động batPack Data Collector (Terminal 3 - CẦN LÀM TRƯỚC)

**QUAN TRỌNG:** Terminal 3 (batPack) PHẢI được khởi động **TRƯỚC** Terminal 2 (Generator)!

```bash
# Terminal 3: Khởi động Network Flow Collector
cd /home/tgf/Documents/DoAn_SDN/thuThapData

# Chạy batPack123.py cho labels 0,1,2,3 (Normal, UDP, SYN, HTTP)
# Chờ khi nào: Generator prompt hiện lên, SAU ĐÓ mới bắt đầu attacks
sudo python3 batPack123.py

# Output sẽ hiện:
# [BATPACK] Đã tạo Named Pipe: zeek_stream.json
# [BATPACK] Interface chọn: s6-eth5
# [BATPACK] Bắt đầu thu thập trên s6-eth5...
```

**Dấu hiệu thành công:**
- "Bắt đầu thu thập" message hiện lên
- **KHÔNG nhấn Ctrl+C! Giữ nó chạy**

---

#### Bước 1.2b: Chạy Data Generator (Terminal 2)
```bash
# Terminal 2: Khởi động generator
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 auto_dataset_generator.py

# Bạn sẽ thấy:
# [GENERATOR] Đang chuẩn bị...
# 👉 BƯỚC: Normal Traffic
# [1] Hãy COPY lệnh dưới đây...
```

**Dấu hiệu thành công:**
- Generator prompt hiện lên
- Chờ bạn input commands

---

#### Bước 1.3: Tạo Normal Traffic (5-10 phút)
```bash
# Terminal 2 sẽ báo:
# 👉 BƯỚC: Normal Traffic
# [1] Copy lệnh này vào Mininet:

# COPY & DÁN vào Terminal 1 (Mininet):
mininet> h2 python -m http.server 8000 > /tmp/http_normal.log 2>&1 &
mininet> h1 for i in $(seq 1 1000); do curl -s http://10.0.2.2:8000 > /dev/null; done

# Chờ 10-15 giây...
# Sau đó BẤM ENTER tại Terminal 2
```

**Output trên Terminal 2:**
```
[GENERATOR] Đang thu thập dữ liệu cho: Normal
[Đang quét] Tiến độ: 50,000/50,000 | raw=500K invalid=0 drop_subnet=0
✅ Đã thu thập xong 50,000 mẫu Normal
```

---

#### Bước 1.4: Tạo UDP Flood (5 phút)
```bash
# Terminal 2 báo:
# 👉 BƯỚC: UDP Flood
# [1] Copy lệnh này:

# COPY & DÁN vào Terminal 1 (Mininet):
mininet> h1 python /home/tgf/Documents/DoAn_SDN/attack/udp_flood.py

# Chờ tự động dừng (5-10 giây)
# BẤM ENTER tại Terminal 2
```

**Output:**
```
[GENERATOR] Đang thu thập dữ liệu cho: UDP Flood
[Đang quét] Tiến độ: 50,000/50,000 | raw=150K invalid=0 drop_subnet=0
✅ Đã thu thập xong 50,000 mẫu UDP Flood
```

---

#### Bước 1.5: Tạo SYN Flood (5 phút)
```bash
# Terminal 2 báo:
# 👉 BƯỚC: SYN Flood

# COPY & DÁN vào Terminal 1:
mininet> h1 python /home/tgf/Documents/DoAn_SDN/attack/syn_flood.py

# BẤM ENTER tại Terminal 2
```

---

#### Bước 1.6: Tạo HTTP Flood (5 phút)
```bash
# Terminal 2 báo:
# 👉 BƯỚC: HTTP Flood

# COPY & DÁN vào Terminal 1:
mininet> h1 python /home/tgf/Documents/DoAn_SDN/attack/http_flood.py

# BẤM ENTER tại Terminal 2
```

---

#### Bước 1.7: Tạo Slowloris (5 phút)
```bash
# ⚠️ TRƯỚC KHI BẬT SLOWLORIS:
# 1. DỪNG Terminal 3 batPack123.py (Ctrl+C)
# 2. KHỞI ĐỘNG Terminal 3 với batPackSL.py (FIFO khác!)

# Terminal 3: Khởi động batPackSL cho Slowloris
sudo python3 batPackSL.py
# Output: [BATPACK] Đã tạo Named Pipe: zeek_stream_slowloris.json

# Sau khi batPackSL chạy, trở về Terminal 2...

# Terminal 2 báo:
# 👉 BƯỚC: Slowloris

# COPY & DÁN vào Terminal 1:
mininet> py [net.get(f'h{i}').cmd('python3 attack/slowloris.py http://10.0.0.11 &') for i in range(1, 11)]

# BẤM ENTER tại Terminal 2
```

**LƯU Ý:**
- batPackSL.py tạo FIFO **KHÁC** (zeek_stream_slowloris.json)
- Timeout dài hơn (30-120s) vì Slowloris giữ kết nối lâu
- Auto_dataset_generator tự động phát hiện & dùng đúng FIFO ✓

---

#### Bước 1.8: Hoàn thành
```bash
# Terminal 2 sẽ báo:
# ✅ TẠO XONG DATASET!
# Output file: master_dataset_v6.csv
# Tổng: 250,000 mẫu (50K × 5 classes)
# Columns: 13 features + target_label

# Kiểm tra file:
cd /home/tgf/Documents/DoAn_SDN
ls -lh master_dataset_v6.csv
wc -l master_dataset_v6.csv
```

**Kết quả dự kiến:**
```
-rw-r--r-- 1 user user 100M Apr 17 10:30 master_dataset_v6.csv
250001 master_dataset_v6.csv  (250K data + 1 header)
```

---

### **GIAI ĐOẠN 2: TRAINING MODELS** (30-60 phút)

#### Bước 2.1: Chuẩn bị
```bash
# Terminal 3 (NEW): Training terminal
cd /home/tgf/Documents/DoAn_SDN
source sdn_env/bin/activate

# Kiểm tra dataset
ls -lh master_dataset_v6.csv  # Phải có file
head -1 master_dataset_v6.csv  # Check header
```

---

#### Bước 2.2: Chạy Training
```bash
# Chạy training (30-60 phút tùy CPU/GPU)
cd ai/
python train_colab_v2.py

# Bạn sẽ thấy output:
```

**Output Chi tiết:**

```
[*] === TRAINING PHASE 1: AUTOENCODER CONTRASTIVE ===
[*] Dataset: 250,000 samples from master_dataset_v6.csv
[*] Features: 13 (will expand to 26 with differential)
[*] Train/Val/Test: 80/20 split → 160K train, 40K test
[*] Epochs: 30 (with early stopping patience=10)
[*] Batch size: 256
[*] Loss: MSE + L2 regularization
[*] Optimizer: Adam (lr=0.001)

Loading dataset...
[PROGRESS] Loaded 250,000 samples
[PROGRESS] Features scaling with StandardScaler
[PROGRESS] Creating sequences with differential features
[PROGRESS] Output shape: [N, 10, 26] ✓

Training Autoencoder Contrastive...
Epoch 1/30: loss=0.0234, val_loss=0.0198 [best]
Epoch 2/30: loss=0.0198, val_loss=0.0189 [best]
...
Epoch 25/30: loss=0.0145, val_loss=0.0152 (early stop patience 5/10)

✅ Phase 1 Done: sdn_autoencoder_contrastive.pth saved

[*] === COMPUTING THRESHOLD ===
Mean reconstruction error: 0.000456
95th percentile: 0.001234
Threshold: 0.001234 ✓

[*] === TRAINING PHASE 2: CLASSIFIER ===
Training Parallel Fusion CNN-GRU...
Epoch 1/50: loss=1.234, val_loss=1.187, acc=0.78
Epoch 2/50: loss=1.145, val_loss=1.098, acc=0.81
...
Epoch 35/50: loss=0.245, val_loss=0.298, acc=0.942 [best] (early stop 2/15)

✅ Phase 2 Done: sdn_model_parallel_fusion.pth saved

[*] === EVALUATION ===
Test Accuracy: 94.2%

Classification Report:
              precision    recall  f1-score
Normal           0.96      0.97      0.96
UDP Flood        0.96      0.95      0.96
SYN Flood        0.93      0.92      0.93
HTTP Flood       0.95      0.94      0.95
Slowloris        0.91      0.92      0.91

✅ Training Complete!
Generated Files:
  ✓ sdn_autoencoder_contrastive.pth (8.5 MB)
  ✓ sdn_model_parallel_fusion.pth (12.3 MB)
  ✓ sdn_scaler.pkl (1.2 MB)
  ✓ ae_threshold.pkl (0.5 KB)
```

**Kiểm tra kết quả:**
```bash
# Xem các file được tạo
ls -lh ai/*.pth ai/*.pkl

# Kết quả dự kiến:
# sdn_autoencoder_contrastive.pth  8.5M
# sdn_model_parallel_fusion.pth   12.3M
# sdn_scaler.pkl                   1.2M
# ae_threshold.pkl                 0.5K
```

---

### **GIAI ĐOẠN 3: TEST END-TO-END** (15-30 phút)

#### Bước 3.1: Khởi động IDS Monitoring
```bash
# Terminal 4 (NEW): Monitoring terminal
cd /home/tgf/Documents/DoAn_SDN
source sdn_env/bin/activate

python ai/ai_monitor.py

# Output sẽ hiện:
# [*] Loading models...
# [*] Loaded: sdn_autoencoder_contrastive.pth ✓
# [*] Loaded: sdn_model_parallel_fusion.pth ✓
# [*] Loaded: sdn_scaler.pkl ✓
# [*] Loaded: ae_threshold.pkl ✓
# [IDS] Initialized ✓
# [*] Waiting for network traffic...
```

---

#### Bước 3.2: Chạy Attack Test
```bash
# Terminal 5 (NEW): Attack terminal
cd /home/tgf/Documents/DoAn_SDN
source sdn_env/bin/activate

# Test Attack 1: UDP Flood
python attack/udp_flood.py

# Chờ 5-10 giây, rồi Ctrl+C

# Test Attack 2: SYN Flood
python attack/syn_flood.py
# Ctrl+C

# Test Attack 3: HTTP Flood
python attack/http_flood.py
# Ctrl+C

# Test Attack 4: Slowloris
python attack/slowloris.py
# Ctrl+C
```

**Output trên Terminal 4 (Monitoring):**
```
[*] Processing flow from 10.0.1.100 (UDP Flood)
[AI] Reconstruction error: 0.00567
[AI] Autoencoder: ANOMALY ✓
[AI] Prediction: UDP_FLOOD (confidence: 0.96)

[Monitor] Processing 1/5 predictions
[*] Status: MONITOR (1/3 attacks)

[*] Processing flow from 10.0.1.100 (Attack 2)
[AI] Prediction: UDP_FLOOD (confidence: 0.97)
[Monitor] Processing 2/5 predictions
[*] Status: MONITOR (2/3 attacks)

[*] Processing flow from 10.0.1.100 (Attack 3)
[AI] Prediction: UDP_FLOOD (confidence: 0.95)
[Monitor] Processing 3/5 predictions
[*] Status: 🛡️ BLOCKED (3/3 attacks threshold reached!)

[IDS] Adding ONOS flow rule...
[ONOS] ✓ Flow rule added: DROP 10.0.1.100 at s6
[ONOS] ✓ Auto-unblock scheduled: 600 seconds

After 600 sec:
[IDS] Auto-unblocking 10.0.1.100 (timeout)
[ONOS] ✓ Flow rule removed
```

---

#### Bước 3.3: Verify ONOS/OVS
```bash
# Kiểm tra OVS flows
sudo ovs-ofctl dump-flows s6

# Hoặc kiểm tra ONOS:
curl -u onos:rocks http://172.17.0.2:8181/onos/v1/flows | python -m json.tool | grep "10.0.1.100"
```

---

## 📊 KỲ VỌNG KẾT QUẢ

### Dataset v6
- ✅ Size: ~100-200 MB
- ✅ Samples: 250,000 (50K × 5 classes)
- ✅ Features: 13 + 1 label
- ✅ Classes: Normal, UDP, SYN, HTTP, Slowloris

### Models Trained
- ✅ Autoencoder Accuracy: Detect anomalies
- ✅ Classifier Accuracy: > 93%
- ✅ Detection Rate: > 90%
- ✅ False Positive Rate: < 5%

### IDS Performance
- ✅ Detection latency: 5-15 ms
- ✅ ONOS DROP execution: Real network blocks
- ✅ Temporal consistency: 3/5 rule working
- ✅ Auto-unblock: 600 second timeout

---

## ⚠️ TROUBLESHOOTING

| Vấn đề | Giải pháp |
|--------|----------|
| Generator không tìm thấy FIFO | Chạy `batPack.py` trong Mininet |
| Dataset quá nhỏ | Chạy lâu hơn, Thu thập thêm 1-2 cycles |
| Training quá chậm | Giảm BATCH_SIZE từ 256 → 128 |
| OOM (Out of Memory) | Giảm batch size, hoặc giảm epochs |
| ONOS không kết nối | Fallback tự động sang OVS ✓ |
| Attacks không phát hiện | Check ai_monitor.py logs |

---

## ✅ CHECKLIST TRƯỚC KHI BẮT ĐẦU

### Terminal Setup (5 Terminals)
```bash
# Terminal 1: Mininet
cd /home/tgf/Documents/DoAn_SDN
python system.py

# Terminal 2: Data Generator
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 auto_dataset_generator.py

# Terminal 3: Network Flow Collector (PHẢI KHỞI ĐỘNG TRƯỚC Terminal 2!)
cd /home/tgf/Documents/DoAn_SDN/thuThapData
# Labels 0,1,2,3:
sudo python3 batPack123.py
# Labels 4 (Slowloris): 
# (Dừng batPack123, rồi chạy:)
sudo python3 batPackSL.py

# Terminals 4 & 5: Dùng sau (training + testing)
```

### Checklist
- [ ] Mininet environment ready
- [ ] Python environment activated: `source sdn_env/bin/activate`
- [ ] Check dataset v3 exists (10K backup)
- [ ] ONOS running (or ready to fallback to OVS)
- [ ] Disk space: > 500 MB free
- [ ] RAM: > 4 GB available
- [ ] Terminal 1 (Mininet) ready
- [ ] Terminal 2 (Generator) ready
- [ ] Terminal 3 (batPack) ready BEFORE starting Terminal 2
- [ ] Sudo access available (for network capture)

---

## 🎯 TIMELINE

```
Giai đoạn 1: Dataset Generation
├─ Chuẩn bị Mininet: 2 phút
├─ Normal Traffic: 8 phút
├─ UDP Flood: 5 phút
├─ SYN Flood: 5 phút
├─ HTTP Flood: 5 phút
└─ Slowloris: 5 phút
   = 30 phút tổng cộng

Giai đoạn 2: Training
├─ Data Loading: 2 phút
├─ Phase 1 (AE): 20 phút (GPU) / 45 phút (CPU)
├─ Phase 2 (Classifier): 15 phút (GPU) / 40 phút (CPU)
└─ Evaluation: 2 phút
   = 40-90 phút (GPU hoặc CPU)

Giai đoạn 3: Testing
├─ IDS startup: 1 phút
├─ UDP Test: 2 phút
├─ SYN Test: 2 phút
├─ HTTP Test: 2 phút
├─ Slowloris Test: 2 phút
└─ Verification: 5 phút
   = 15 phút tổng cộng

TOTAL: 1.5 - 2 giờ (GPU)
       2 - 3 giờ (CPU)
```

---

## 🎉 HOÀN THÀNH

Sau khi hoàn tất 3 giai đoạn:
- ✅ Dataset v6 tạo xong (250K samples)
- ✅ Models trained (Contrastive AE + Parallel Fusion)
- ✅ End-to-end testing verified
- ✅ ONOS/OVS integration working
- ✅ **System ready for production!**

---

## 📞 CÓ VẤN ĐỀ?

1. **Check logs:** `tail -f /tmp/ids_onos.log`
2. **Verify files:** `ls -la ai/*.pth ai/*.pkl master_dataset_v6.csv`
3. **Test connection:** `curl http://172.17.0.2:8181/onos/v1/devices`
4. **Debug:** `python -c "import torch; print(torch.__version__)"`

---

**Bắt đầu ngay! 🚀**

