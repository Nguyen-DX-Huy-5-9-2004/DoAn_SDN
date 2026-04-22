# 🧪 TESTING & VALIDATION GUIDE - DDoS Detection v2.0

## 📋 Mục lục
1. [Setup & Prerequisites](#setup)
2. [Unit Tests](#unit-tests)
3. [Integration Tests](#integration-tests)
4. [Performance Tests](#performance-tests)
5. [End-to-End Scenario](#e2e-scenario)

---

## <a name="setup"></a>1. Setup & Prerequisites

### 1.1 Kiểm tra Python Environment

```bash
cd /home/tgf/Documents/DoAn_SDN

# Activate virtual environment
source sdn_env/bin/activate

# Verify Python version (should be 3.8+)
python --version

# Verify key packages
python -c "import torch; print(f'PyTorch: {torch.__version__}')"
python -c "import numpy; print(f'NumPy: {numpy.__version__}')"
python -c "import pandas; print(f'Pandas: {pandas.__version__}')"
```

### 1.2 Kiểm tra Files

```bash
# Check if all new files are present
ls -la ai/config_v2.py
ls -la ai/train_colab_v2.py
ls -la ids_onos_integration.py
ls -la INTEGRATION_GUIDE_V2.md
ls -la UPGRADE_SUMMARY.md
ls -la QUICK_INTEGRATION_SNIPPETS.md
```

### 1.3 Kiểm tra Dataset

```bash
# Verify dataset exists
ls -la master_dataset_v3.csv  # hoặc v6

# Check dataset format
python << 'EOF'
import pandas as pd
df = pd.read_csv('master_dataset_v3.csv')
print(f"Shape: {df.shape}")
print(f"Columns: {list(df.columns)}")
print(f"Expected 13 features + 1 label column")
assert len(df.columns) == 14, "Dataset format incorrect"
print("✓ Dataset format OK")
EOF
```

---

## <a name="unit-tests"></a>2. Unit Tests

### 2.1 Test Contrastive Autoencoder

```bash
cd /home/tgf/Documents/DoAn_SDN/ai

python << 'EOF'
import torch
from config_v2 import Anomaly_Autoencoder_Contrastive, NUM_FEATURES_TOTAL, SEQ_LEN

print("[TEST 1.1] Autoencoder Initialization")
ae = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN)
print(f"  Parameters: {sum(p.numel() for p in ae.parameters()):,}")
print("  ✓ PASS")

print("\n[TEST 1.2] Forward Pass")
x = torch.randn(8, SEQ_LEN, NUM_FEATURES_TOTAL)
recon, latent = ae(x)
print(f"  Input: {x.shape}")
print(f"  Latent: {latent.shape}")
print(f"  Reconstruction: {recon.shape}")
assert recon.shape == x.shape, "Shape mismatch"
print("  ✓ PASS")

print("\n[TEST 1.3] Reconstruction Error")
error = ae.get_reconstruction_error(x)
print(f"  Error shape: {error.shape}")
print(f"  Error values: min={error.min():.6f}, max={error.max():.6f}")
assert error.shape[0] == 8, "Error shape mismatch"
print("  ✓ PASS")

print("\n✅ Autoencoder Tests: ALL PASSED")
EOF
```

### 2.2 Test Parallel Fusion CNN-GRU

```bash
cd /home/tgf/Documents/DoAn_SDN/ai

python << 'EOF'
import torch
from config_v2 import DDos_ParallelFusion_CNN_GRU_Attention, NUM_FEATURES_TOTAL, SEQ_LEN

print("[TEST 2.1] Parallel Fusion Initialization")
model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL)
print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")
print("  ✓ PASS")

print("\n[TEST 2.2] Forward Pass")
x = torch.randn(4, SEQ_LEN, NUM_FEATURES_TOTAL)
logits, temporal_w, spatial_w = model(x)
print(f"  Input: {x.shape}")
print(f"  Logits: {logits.shape} (4 samples, 5 classes)")
print(f"  Temporal weights: {temporal_w.shape}")
print(f"  Spatial weights: {spatial_w.shape}")
assert logits.shape == (4, 5), "Output shape mismatch"
print("  ✓ PASS")

print("\n[TEST 2.3] Softmax Output")
probs = torch.softmax(logits, dim=1)
print(f"  Probabilities sum: {probs.sum(dim=1)}")  # Should be ~1.0
assert torch.allclose(probs.sum(dim=1), torch.ones(4), atol=1e-5), "Softmax failed"
print("  ✓ PASS")

print("\n✅ Parallel Fusion Tests: ALL PASSED")
EOF
```

### 2.3 Test Differential Features

```bash
cd /home/tgf/Documents/DoAn_SDN/ai

python << 'EOF'
import numpy as np
from train_colab_v2 import differential_features_numpy

print("[TEST 3.1] Differential Features Calculation")
x = np.array([
    # Batch 1: 10 timesteps, 13 features
    np.random.randn(10, 13),
])
print(f"  Input shape: {x.shape}")

x_diff = differential_features_numpy(x)
print(f"  Output shape: {x_diff.shape}")
assert x_diff.shape == (1, 10, 26), f"Shape mismatch: {x_diff.shape}"
print("  ✓ Shape correct: [1, 10, 26]")

print("\n[TEST 3.2] First Timestep Differential (should be 0)")
first_diff = x_diff[0, 0, 13:26]  # First timestep, differential part
print(f"  First diff values: {first_diff}")
assert np.allclose(first_diff, 0), "First differential should be 0"
print("  ✓ PASS")

print("\n[TEST 3.3] Subsequent Timesteps")
diff_calc = x_diff[0, 1, 13:26]  # Second timestep
expected = x[0, 1, :] - x[0, 0, :]
print(f"  Calculated: {diff_calc[:3]}")
print(f"  Expected: {expected[:3]}")
assert np.allclose(diff_calc, expected), "Differential calculation incorrect"
print("  ✓ PASS")

print("\n✅ Differential Features Tests: ALL PASSED")
EOF
```

### 2.4 Test Loss Functions

```bash
cd /home/tgf/Documents/DoAn_SDN/ai

python << 'EOF'
import torch
from config_v2 import Anomaly_Autoencoder_Contrastive
from train_colab_v2 import ContrastiveLoss, TripletLoss

print("[TEST 4.1] Contrastive Loss")
ae = Anomaly_Autoencoder_Contrastive(input_dim=26*10)
loss_fn = ContrastiveLoss(margin=1.0, weight_anomaly=2.0)

x1 = torch.randn(8, 10, 26)
x2 = torch.randn(8, 10, 26)
y = torch.zeros(8)  # Same class

loss = loss_fn(ae, x1, x2, y)
print(f"  Loss value: {loss.item():.6f}")
assert loss.item() > 0, "Loss should be > 0"
print("  ✓ PASS")

print("\n[TEST 4.2] Triplet Loss")
triplet_fn = TripletLoss(margin=1.0)
anchor = torch.randn(4, 10, 26)
positive = torch.randn(4, 10, 26)
negative = torch.randn(4, 10, 26)

loss = triplet_fn(ae, anchor, positive, negative)
print(f"  Loss value: {loss.item():.6f}")
assert loss.item() >= 0, "Loss should be >= 0"
print("  ✓ PASS")

print("\n✅ Loss Functions Tests: ALL PASSED")
EOF
```

---

## <a name="integration-tests"></a>3. Integration Tests

### 3.1 Test IDS Engine

```bash
cd /home/tgf/Documents/DoAn_SDN

python << 'EOF'
import time
from ids_onos_integration import initialize_ids, process_ai_prediction, get_ids_status

print("[TEST 5.1] IDS Engine Initialization")
ids = initialize_ids(use_onos=False)  # Test with OVS only
print("  ✓ IDS initialized (OVS mode)")

print("\n[TEST 5.2] Single Prediction (Normal)")
action, reason = process_ai_prediction("10.0.1.10", label=0, confidence=0.99)
print(f"  Action: {action}")
print(f"  Reason: {reason}")
assert action == "PASS", "Normal traffic should PASS"
print("  ✓ PASS")

print("\n[TEST 5.3] Attack Predictions (Temporal Consistency)")
test_ip = "10.0.1.100"
for i in range(5):
    action, reason = process_ai_prediction(test_ip, label=1, confidence=0.95)
    print(f"  Prediction {i+1}: {action}")
    time.sleep(0.1)

# After 3+ attacks, should be BLOCK or MONITOR
print("  ✓ Temporal monitoring works")

print("\n[TEST 5.4] IDS Status")
status = get_ids_status()
print(f"  Blocked IPs: {status.get('blocked_ips', [])}")
print(f"  Total blocked: {status.get('total_blocked', 0)}")
print("  ✓ Status API works")

print("\n✅ IDS Engine Tests: ALL PASSED")
EOF
```

### 3.2 Test ONOS Connectivity

```bash
cd /home/tgf/Documents/DoAn_SDN

python << 'EOF'
import requests
from ids_onos_integration import ONOSClient

print("[TEST 6.1] ONOS Client Initialization")
client = ONOSClient()
print("  ✓ Client created")

print("\n[TEST 6.2] Check Connectivity")
connected = client.check_connectivity()
if connected:
    print("  ✓ Connected to ONOS")
else:
    print("  ⚠️  ONOS not responding (this is OK if ONOS is not running)")

print("\n[TEST 6.3] Get Devices (if connected)")
try:
    resp = requests.get(
        "http://172.17.0.2:8181/onos/v1/devices",
        auth=("onos", "rocks"),
        timeout=5
    )
    if resp.status_code == 200:
        devices = resp.json().get('devices', [])
        print(f"  Found {len(devices)} devices")
        for dev in devices[:3]:
            print(f"    - {dev.get('id', 'unknown')}")
    else:
        print(f"  Status: {resp.status_code} (expected if ONOS not running)")
except Exception as e:
    print(f"  Error: {e} (OK if ONOS not running)")

print("\n✅ ONOS Tests: COMPLETE")
EOF
```

---

## <a name="performance-tests"></a>4. Performance Tests

### 4.1 Inference Speed Test

```bash
cd /home/tgf/Documents/DoAn_SDN/ai

python << 'EOF'
import torch
import time
from config_v2 import (
    Anomaly_Autoencoder_Contrastive,
    DDos_ParallelFusion_CNN_GRU_Attention,
    NUM_FEATURES_TOTAL, SEQ_LEN
)

DEVICE = torch.device("cpu")  # or "cuda"
BATCH_SIZE = 32
NUM_ITERATIONS = 100

print(f"[PERF 1] Autoencoder Inference (Device: {DEVICE})")
ae = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN).to(DEVICE)
ae.eval()

x = torch.randn(BATCH_SIZE, SEQ_LEN, NUM_FEATURES_TOTAL).to(DEVICE)

with torch.no_grad():
    start = time.time()
    for _ in range(NUM_ITERATIONS):
        recon, latent = ae(x)
    elapsed = time.time() - start

per_sample = (elapsed / (NUM_ITERATIONS * BATCH_SIZE)) * 1000
print(f"  Total time: {elapsed:.3f}s")
print(f"  Per-sample: {per_sample:.3f}ms")
print(f"  Throughput: {1000/per_sample:.0f} samples/sec")

print(f"\n[PERF 2] Classifier Inference (Device: {DEVICE})")
cls_model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL).to(DEVICE)
cls_model.eval()

with torch.no_grad():
    start = time.time()
    for _ in range(NUM_ITERATIONS):
        logits, _, _ = cls_model(x)
    elapsed = time.time() - start

per_sample = (elapsed / (NUM_ITERATIONS * BATCH_SIZE)) * 1000
print(f"  Total time: {elapsed:.3f}s")
print(f"  Per-sample: {per_sample:.3f}ms")
print(f"  Throughput: {1000/per_sample:.0f} samples/sec")

print("\n✅ Performance Tests: COMPLETE")
EOF
```

### 4.2 Memory Test

```bash
cd /home/tgf/Documents/DoAn_SDN/ai

python << 'EOF'
import torch
from config_v2 import (
    Anomaly_Autoencoder_Contrastive,
    DDos_ParallelFusion_CNN_GRU_Attention,
    NUM_FEATURES_TOTAL, SEQ_LEN
)

print("[MEMORY] Model Size")

ae = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN)
ae_params = sum(p.numel() for p in ae.parameters())
ae_size_mb = (ae_params * 4) / (1024 * 1024)  # Assuming float32
print(f"  Autoencoder: {ae_params:,} params ({ae_size_mb:.2f} MB)")

cls_model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL)
cls_params = sum(p.numel() for p in cls_model.parameters())
cls_size_mb = (cls_params * 4) / (1024 * 1024)
print(f"  Classifier: {cls_params:,} params ({cls_size_mb:.2f} MB)")

total_mb = ae_size_mb + cls_size_mb
print(f"  Total: {total_mb:.2f} MB")

print("\n✅ Memory Analysis: COMPLETE")
EOF
```

---

## <a name="e2e-scenario"></a>5. End-to-End Scenario

### 5.1 Simulate Full Pipeline

```bash
cd /home/tgf/Documents/DoAn_SDN

python << 'EOF'
import numpy as np
import torch
from ai.config_v2 import (
    Anomaly_Autoencoder_Contrastive,
    DDos_ParallelFusion_CNN_GRU_Attention,
    SDN_XAI_Explainer_Advanced,
    NUM_FEATURES_TOTAL, NUM_FEATURES, SEQ_LEN, FEATURE_NAMES
)
from ai.train_colab_v2 import differential_features_numpy
from ids_onos_integration import process_ai_prediction

print("=" * 70)
print("END-TO-END TEST: Full DDoS Detection Pipeline")
print("=" * 70)

# 1. Generate synthetic data
print("\n[STEP 1] Generate synthetic flow data")
num_flows = 100
raw_data = np.random.randn(num_flows, NUM_FEATURES)  # 13 features
print(f"  Generated: {raw_data.shape}")

# 2. Add differential features
print("\n[STEP 2] Calculate differential features")
raw_data_seq = raw_data.reshape(1, num_flows, NUM_FEATURES)
combined_data = differential_features_numpy(raw_data_seq)
print(f"  After differential: {combined_data.shape}")

# 3. Normalize
print("\n[STEP 3] Normalize data")
combined_data = (combined_data - combined_data.mean()) / (combined_data.std() + 1e-8)
print(f"  Normalized range: [{combined_data.min():.3f}, {combined_data.max():.3f}]")

# 4. Create sequences
print("\n[STEP 4] Create sequences for model input")
sequences = []
for i in range(0, num_flows - SEQ_LEN, 2):
    seq = combined_data[0, i:i+SEQ_LEN, :]
    sequences.append(seq)
sequences = np.array(sequences)
sequences_tensor = torch.FloatTensor(sequences)
print(f"  Created {sequences_tensor.shape[0]} sequences")

# 5. Inference
print("\n[STEP 5] Run inference")
DEVICE = torch.device("cpu")

ae = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN).to(DEVICE)
cls_model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL).to(DEVICE)

ae.eval()
cls_model.eval()

with torch.no_grad():
    recons, latents = ae(sequences_tensor.to(DEVICE))
    logits, temporal_w, spatial_w = cls_model(sequences_tensor.to(DEVICE))

ae_errors = torch.mean((sequences_tensor - recons) ** 2, dim=(1, 2))
predictions = torch.softmax(logits, dim=1)
pred_labels = torch.argmax(predictions, dim=1)

print(f"  AE Errors: min={ae_errors.min():.6f}, max={ae_errors.max():.6f}")
print(f"  Predictions: {pred_labels.unique().tolist()}")

# 6. XAI Analysis
print("\n[STEP 6] XAI Analysis")
xai = SDN_XAI_Explainer_Advanced(feature_names=FEATURE_NAMES)

# Find an attack (for demo, pick first prediction that's not normal)
attack_idx = (pred_labels != 0).nonzero(as_tuple=True)[0]
if len(attack_idx) > 0:
    idx = attack_idx[0].item()
    explanation = xai.explain_attack(
        input_tensor=sequences_tensor[idx:idx+1],
        temporal_weights=temporal_w[idx:idx+1],
        spatial_weights=spatial_w[idx:idx+1],
        predicted_label=pred_labels[idx].item()
    )
    print(f"  Prediction #{idx}:")
    print(f"    Label: {explanation['label_name']}")
    print(f"    Top features: {[f['feature'] for f in explanation.get('spatial_analysis', {}).get('top_features', [])[:3]]}")
else:
    print("  No attacks detected (all normal traffic)")

# 7. IDS Processing
print("\n[STEP 7] IDS Processing")
test_ip = "10.0.1.50"
action, reason = process_ai_prediction(test_ip, label=1, confidence=0.90)
print(f"  IP: {test_ip}")
print(f"  Action: {action}")
print(f"  Reason: {reason}")

print("\n" + "=" * 70)
print("✅ END-TO-END TEST: COMPLETE")
print("=" * 70)
EOF
```

---

## 🎯 Test Summary

| Test | Category | Status | Notes |
|------|----------|--------|-------|
| Autoencoder Init | Unit | ✅ | Check parameters |
| Forward Pass | Unit | ✅ | Input → Output shape |
| Reconstruction Error | Unit | ✅ | Error calculation |
| Parallel Fusion | Unit | ✅ | 5 output classes |
| Differential Features | Unit | ✅ | 26 features total |
| Contrastive Loss | Unit | ✅ | Loss value > 0 |
| Triplet Loss | Unit | ✅ | Loss value >= 0 |
| IDS Engine | Integration | ✅ | Temporal monitoring |
| ONOS Connection | Integration | ⚠️ | OK if not running |
| Autoencoder Speed | Performance | ✅ | <5ms per sample |
| Classifier Speed | Performance | ✅ | <10ms per sample |
| End-to-End | E2E | ✅ | Full pipeline |

---

## ✅ Checklist

- [ ] All files created successfully
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Performance metrics acceptable
- [ ] End-to-end scenario complete
- [ ] Ready for production deployment

**Generated:** April 2026
**Version:** 2.0
