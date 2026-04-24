# 🛡️ HƯỚNG DẪN TÍCH HỢP - DDoS Detection v2.0 Upgrade

## 📋 Tóm tắt nâng cấp

Dự án đã được nâng cấp từ **13 đặc trưng** lên **26 đặc trưng** với kiến trúc học sâu cải tiến.

| Yếu tố | Trước | Sau | Cải thiện |
|--------|-------|-----|---------|
| Đặc trưng | 13 (gốc) | 26 (13 gốc + 13 biến thiên) | Bắt được sự biến thiên bất thường |
| Autoencoder Loss | MSE cơ bản | Contrastive/Triplet Loss | Phân biệt tốt hơn Normal vs Attack |
| Kiến trúc Classifier | Sequential CNN→GRU | Parallel CNN+GRU Fusion | Bắt cả spatial + temporal patterns |
| XAI Engine | Cơ bản | Advanced (giải thích differential) | Hiểu rõ hơn lý do quyết định |
| IPS Execution | In thông báo | ONOS/OVS Flow Rules | Thực hiện DROP thực tế |

---

## 🚀 PHẦN 1: CẬP NHẬT CƠ CẤU HÌNH

### 1.1 Cập nhật `config.py` → `config_v2.py`

**File mới:** `ai/config_v2.py` (đã tạo)

**Các thay đổi chính:**
- NUM_FEATURES: 13 → 26
- Thêm differential feature names
- Thêm ONOS/OVS configuration
- Thêm AttentionLayer (nếu bị thiếu)
- Implement DDos_ParallelFusion_CNN_GRU_Attention (CNN+GRU song song)
- Implement SDN_XAI_Explainer_Advanced (giải thích differential)

**Cách sử dụng:**
```python
# Thay đổi import từ:
from config import NUM_FEATURES, Anomaly_Autoencoder, ...

# Thành:
from config_v2 import (
    NUM_FEATURES_TOTAL, 
    Anomaly_Autoencoder_Contrastive,
    DDos_ParallelFusion_CNN_GRU_Attention,
    FEATURE_NAMES
)
```

---

## 🎓 PHẦN 2: HUẤN LUYỆN MÔ HÌNH

### 2.1 Sử dụng `train_colab_v2.py`

**File mới:** `ai/train_colab_v2.py` (đã tạo)

**Các cải thiện:**
- ✅ Contrastive Learning cho Autoencoder
- ✅ Tích hợp Differential Features vào pipeline
- ✅ Hỗ trợ 26 đặc trưng toàn bộ
- ✅ Kiến trúc Parallel Fusion
- ✅ Focal Loss cho lớp không cân bằng

**Hướng dẫn chạy:**

1. **Chuẩn bị dữ liệu:**
   ```bash
   cd /home/tgf/Documents/DoAn_SDN
   
   # Đảm bảo có dataset (hoặc sinh mới)
   python thuThapData/auto_dataset_generator.py
   ```

2. **Chạy huấn luyện:**
   ```bash
   cd ai/
   python train_colab_v2.py
   ```

3. **Output models:**
   - `sdn_autoencoder_contrastive.pth` - Autoencoder với Contrastive Learning
   - `sdn_model_parallel_fusion.pth` - Classifier với Parallel Fusion
   - `sdn_scaler.pkl` - StandardScaler
   - `ae_threshold.pkl` - Reconstruction error threshold

---

## 🔌 PHẦN 3: TÍCH HỢP IDS + ONOS/OVS

### 3.1 Sử dụng `ids_onos_integration.py`

**File mới:** `ids_onos_integration.py` (tại thư mục gốc)

**Các tính năng:**
- ✅ Temporal Consistency Monitoring (theo dõi lịch sử dự đoán)
- ✅ ONOS REST API integration (tối ưu)
- ✅ OVS-ofctl fallback (khi ONOS không available)
- ✅ Auto-unblock sau timeout
- ✅ Logging đầy đủ

### 3.2 Tích hợp vào `ai_monitor.py`

**Trong file `ai/ai_monitor.py`, thêm:**

```python
# ===== Tại đầu file =====
from ids_onos_integration import process_ai_prediction, initialize_ids

# ===== Trong hàm khởi tạo =====
def initialize_monitoring():
    global ids_engine
    # Initialize IDS Engine
    ids_engine = initialize_ids(use_onos=True)  # Hoặc False nếu dùng OVS fallback
    logger.info("[Monitor] IDS Engine initialized")

# ===== Thay đổi hàm xử lý dự đoán =====
def process_predictions(predictions, ae_reconstructions):
    """
    Hàm được gọi khi có dự đoán mới từ mô hình
    """
    for idx, pred in enumerate(predictions):
        src_ip = pred.get('src_ip')
        predicted_label = pred.get('label')
        confidence = pred.get('confidence', 1.0)
        
        # ===== GỌI IDS ENGINE (THAY VÌ apply_ips_decision cũ) =====
        action, reason = process_ai_prediction(src_ip, predicted_label, confidence)
        
        if action == "BLOCK":
            logger.warning(f"🛡️ BLOCKED {src_ip}: {reason}")
        elif action == "MONITOR":
            logger.info(f"📊 MONITORING {src_ip}: {reason}")
        else:
            logger.debug(f"✓ PASS {src_ip}")
```

### 3.3 Tích hợp vào `system.py`

**Thay thế hàm `apply_ips_decision` cũ:**

```python
# ===== Tại đầu system.py, thêm =====
from ids_onos_integration import process_ai_prediction, initialize_ids

# ===== Trong hàm start_network() =====
def start_network():
    # ... code existing ...
    
    # Initialize IDS + ONOS
    ids_engine = initialize_ids(use_onos=True)
    logger.info("[Network] IDS Engine ready")
    
    # ... rest of code ...

# ===== Thay thế hàm apply_ips_decision =====
def apply_ips_decision(net, src_ip, label, confidence):
    """
    PHIÊN BẢN MỚI: Sử dụng IDS Engine với ONOS/OVS integration
    """
    action, reason = process_ai_prediction(src_ip, label, confidence)
    return action
```

---

## 📊 PHẦN 4: GIẢI THÍCH AI (XAI)

### 4.1 Sử dụng XAI Explainer nâng cấp

**Trong `ai_monitor.py` hoặc `system.py`:**

```python
from config_v2 import SDN_XAI_Explainer_Advanced

# Khởi tạo
xai_engine = SDN_XAI_Explainer_Advanced()

# Sau khi có dự đoán
prediction, temporal_weights, spatial_weights = cls_model(input_data)

# Giải thích
explanation = xai_engine.explain_attack(
    input_tensor=input_data,
    temporal_weights=temporal_weights,
    spatial_weights=spatial_weights,
    predicted_label=predicted_label
)

print(explanation["explanation_text"])
# Output:
# 🚨 PHÁT HIỆN UDP_FLOOD 🚨
#
# ⏱️  PHÂN TÍCH THỜI GIAN:
# - Flow bất thường nhất: #5 (Tầm quan trọng: 78.3%)
#
# 📊 PHÂN TÍCH ĐẶC TRƯNG (Top 3):
#   1. d_Packet_Rate (Differential): Sự thay đổi trong Packet_Rate từ flow trước rất bất thường
#   2. Packet_Rate (Original): Packet_Rate có giá trị bất thường
#   3. d_Byte_Rate (Differential): Sự thay đổi trong Byte_Rate từ flow trước rất bất thường
```

---

## 🧪 PHẦN 5: KIỂM THỬ

### 5.1 Unit test cho Contrastive Loss

```python
# ai/test_contrastive_loss.py

import torch
from config_v2 import Anomaly_Autoencoder_Contrastive
from train_colab_v2 import ContrastiveLoss

# Khởi tạo
ae = Anomaly_Autoencoder_Contrastive(input_dim=26*10)
loss_fn = ContrastiveLoss(margin=1.0)

# Tạo dữ liệu test
x1 = torch.randn(32, 10, 26)  # Normal flow 1
x2 = torch.randn(32, 10, 26)  # Normal flow 2 (cùng loại)
y = torch.zeros(32)            # y=0 (cùng loại)

# Tính loss
loss = loss_fn(ae, x1, x2, y)
print(f"Contrastive Loss: {loss.item():.6f}")
```

### 5.2 Unit test cho Parallel Fusion

```python
# ai/test_parallel_fusion.py

import torch
from config_v2 import DDos_ParallelFusion_CNN_GRU_Attention

# Khởi tạo
model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=26)

# Dữ liệu test
x = torch.randn(8, 10, 26)  # Batch=8, Seq_len=10, Features=26

# Forward pass
logits, temporal_weights, spatial_weights = model(x)

print(f"Output shape: {logits.shape}")  # [8, 5] - 5 classes
print(f"Temporal weights: {temporal_weights.shape}")  # [8, 10]
print(f"Spatial weights: {spatial_weights.shape}")    # [8, 10, 26]
```

### 5.3 Integration test cho IDS + ONOS

```bash
# Test ONOS connectivity
cd /home/tgf/Documents/DoAn_SDN
python -c "from ids_onos_integration import ONOSClient; \
           client = ONOSClient(); \
           print('ONOS connected:', client.check_connectivity())"

# Test IDS Engine
python ids_onos_integration.py
```

---

## 📈 PHẦN 6: MONITORING & LOGGING

### 6.1 Log locations

- **IDS Log:** `/tmp/ids_onos.log`
- **System Log:** `/tmp/ips_actions.log`
- **Training Log:** `ai/training_*.log` (nếu setup)

### 6.2 Xem trạng thái IDS

```python
from ids_onos_integration import get_ids_status

status = get_ids_status()
print(f"Blocked IPs: {status['blocked_ips']}")
print(f"Monitoring IPs: {status['monitoring_ips']}")
print(f"Total blocked: {status['total_blocked']}")
```

---

## 🔄 PHẦN 7: MIGRATION PATH (From v1 → v2)

### 7.1 Nếu bạn có model cũ:

1. **Giữ lại config.py cũ** (để không break existing code)
2. **Tạo config_v2.py** (đã làm)
3. **Tạo train_colab_v2.py** (đã làm)
4. **Chạy training từ đầu** (model cũ không tương thích):
   ```bash
   cd ai/
   python train_colab_v2.py
   ```

### 7.2 Cơ chế hoạt động song song:

```python
# Có thể chạy cả v1 và v2 cùng lúc
from config import Anomaly_Autoencoder as AE_v1          # 13 features
from config_v2 import Anomaly_Autoencoder_Contrastive as AE_v2  # 26 features

# So sánh hiệu suất
ae_v1 = AE_v1()
ae_v2 = AE_v2()
```

---

## 📝 PHẦN 8: TROUBLESHOOTING

### Q: ONOS không phản hồi?
**A:** IDS engine sẽ tự động fallback sang OVS-ofctl
```bash
# Kiểm tra ONOS
curl http://172.17.0.2:8181/onos/v1/devices -u onos:rocks

# Kiểm tra OVS
ovs-ofctl show s6
```

### Q: Model training quá lâu?
**A:** Giảm `EPOCHS_AE` và `EPOCHS_CLS` trong `train_colab_v2.py`
```python
EPOCHS_AE = 15   # Thay vì 30
EPOCHS_CLS = 25  # Thay vì 50
```

### Q: OOM (Out of Memory)?
**A:** Giảm `BATCH_SIZE`
```python
BATCH_SIZE = 128  # Thay vì 256
```

### Q: Dataset không tương thích?
**A:** Đảm bảo dataset có đúng 13 cột features:
```python
FEATURE_NAMES_ORIGINAL = [
    "Src_Port", "Dst_Port", "Protocol", "Duration_Sec", 
    "Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets", 
    "Conn_State", "L7_App_Protocol", "Packet_Rate", "Byte_Rate", "Anomaly_Score"
]
```

---

## ✅ CHECKLIST - Các bước đầy đủ để triển khai

- [ ] Tạo `config_v2.py`
- [ ] Tạo `train_colab_v2.py`
- [ ] Tạo `ids_onos_integration.py`
- [ ] Chạy `train_colab_v2.py` để sinh model mới
- [ ] Cập nhật `ai_monitor.py` để sử dụng `ids_onos_integration.py`
- [ ] Cập nhật `system.py` để gọi `process_ai_prediction()`
- [ ] Test IDS engine: `python ids_onos_integration.py`
- [ ] Kiểm tra ONOS/OVS connectivity
- [ ] Chạy network simulation với tấn công test

---

## 📚 THAM KHẢO KIẾN THỨC

### Differential Features
- Tính sự thay đổi: `d_X[t] = X[t] - X[t-1]`
- Giúp phát hiện "burst" attack (tăng đột ngột)
- Ví dụ: UDP Flood có d_Packet_Rate rất cao

### Contrastive Learning
- Normal flows → Reconstruct well (MSE thấp)
- Attack flows → Reconstruct poorly (MSE cao)
- Autoencoder học phân biệt 2 lớp

### Parallel Fusion
- CNN branch: Bắt spatial patterns (mối quan hệ giữa features)
- GRU branch: Bắt temporal patterns (hành vi theo thời gian)
- Fusion: Ghép 2 branch → Decision

### XAI (Explainable AI)
- Spatial Attention: "Đặc trưng nào quan trọng?"
- Temporal Attention: "Flow nào bất thường?"
- Differential Analysis: "Có sự biến thiên bất thường không?"

---

## 🎯 Mục tiêu đạt được

✓ 26 đặc trưng (13 gốc + 13 biến thiên)
✓ Contrastive Learning (tách Normal vs Attack)
✓ Parallel Fusion Architecture (CNN + GRU song song)
✓ Advanced XAI (giải thích chi tiết)
✓ ONOS/OVS Integration (DROP thực tế)
✓ Temporal Consistency (5 flow thì 3 attack → BLOCK)

---

**Created:** 2024
**Version:** 2.0 (Upgrade từ v1.0)
**Status:** Ready for Deployment ✅
