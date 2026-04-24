# 🎯 Data Collection Optimization - Execution Checklist

## Pre-Execution Setup

### 1. Environment Preparation
```bash
cd /home/tgf/Documents/DoAn_SDN

# Activate virtual environment
source sdn_env/bin/activate

# Verify dependencies
pip install -q nfstream requests

# Create logs directory if not exists
mkdir -p logs/

# Verify interface (should be s6-eth1)
ip link show | grep s6-eth1
```

### 2. Pre-Collection Verification
```bash
# Check that markers can be created
touch ai/.marker_test
ls -la ai/.marker_test
rm ai/.marker_test

# Verify FIFO paths exist or can be created
ls -la ai/*.json 2>/dev/null || echo "FIFOs will be created by batPack_v2"

# Confirm Mininet is running
containernet> net.hosts
# Should show: [h1, h2, ... web1, proxy1, ...]
```

### 3. Database/File Cleanup
```bash
# Back up any previous dataset
cp thuThapData/master_dataset_v7.csv thuThapData/master_dataset_v7.csv.backup 2>/dev/null || echo "No previous dataset"

# Remove old CSV to start fresh
rm -f thuThapData/master_dataset_v7.csv

# Check disk space (need ~500MB for 520k samples)
df -h . | tail -1
```

---

## Execution Steps

### Terminal 1: Start batPack_v2 (Automatic timeout switching)

```bash
cd /home/tgf/Documents/DoAn_SDN

# Start batPack with logging
sudo python3 ai/batPack_v2.py

# Expected output:
# [INFO] - [CONFIG] IFACE: s6-eth1
# [INFO] - [CONFIG] Output FIFOs: ./ai/zeek_stream.json + ./ai/zeek_stream_slowloris.json
# [INFO] - [CONFIG] Batch size: 50, Interval: 1.0s
# [INFO] - [CONFIG] Timeout Profile: Normal: Standard bidirectional flows
# [INFO] - [CONFIG] ACTIVE_TIMEOUT=10s, IDLE_TIMEOUT=5s
# [INFO] - [WAIT] No marker found, waiting for generator signal...
```

**Keep this running for entire collection** (90+ minutes)

---

### Terminal 2: Start Data Collection (Orchestrated phases)

```bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData

# Start collection with new optimized phase ordering
sudo python3 auto_dataset_generator.py

# Expected phases (automatic sequencing):

# ============= PHASE 0: NORMAL TRAFFIC =============
# [PHASE 0️⃣ ] NORMAL TRAFFIC - 50 min (FIRST)
# [💡] Chỉ bắt traffic từ clients (10.0.2.x) → web servers
# [MARKER] Created .marker_normal for phase 0
# [Input] Press ENTER to start normal traffic collection...
# 
# [In Mininet]
# > web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000 &'
# > [Press ENTER to continue in main terminal]
#
# [Collection Progress] Tiến độ: 10,000/200,000 | raw=45,230 invalid=2,100 drop_subnet=32,000
#
# [Wait ~50 minutes for 200,000 normal samples]

# ============= PHASE 1: UDP FLOOD =============
# [PHASE 1️⃣ ] UDP FLOOD ATTACK - 10 min
# [💡] UDP: Unidirectional, chỉ gửi không chờ nhận
# [*] Tuning: Shorter timeouts (ACTIVE=3s, IDLE=1s)
# [MARKER] Created .marker_udp for phase 1
#
# [In Mininet]
# > py [net.get(f'h{i}').cmd('python3 attack/udp_flood.py 10.0.0.10 &') for i in range(1, 5)]
# > [Press ENTER to continue]
#
# [Collection in fast mode - 1s timeout for unidirectional flows]
# [Wait ~10 minutes for 80,000 UDP samples]

# ============= PHASE 2: SYN FLOOD =============
# [PHASE 2️⃣ ] SYN FLOOD ATTACK - 10 min
# [💡] SYN: Half-open connections, bắt incomplete 3-way handshake
# [*] Tuning: Medium timeouts (ACTIVE=5s, IDLE=2s)
# [MARKER] Created .marker_syn for phase 2
#
# [In Mininet]
# > py [net.get(f'h{i}').cmd('python3 attack/syn_flood.py 10.0.0.10 &') for i in range(6, 11)]
# > [Press ENTER to continue]
#
# [Collection in medium mode - 2s timeout for half-open connections]
# [Wait ~10 minutes for 80,000 SYN samples]

# ============= PHASE 3: HTTP FLOOD =============
# [PHASE 3️⃣ ] HTTP FLOOD ATTACK - 10 min
# [💡] HTTP: Layer 7, bắt request HTTP floods
# [*] Tuning: Standard HTTP timeouts (ACTIVE=8s, IDLE=3s)
# [MARKER] Created .marker_http for phase 3
#
# [In Mininet - Hash variant]
# > py [net.get(f'h{i}').cmd('python3 attack/http_flood.py http://10.0.0.10:8000 hash &') for i in range(11, 15)]
# > [Press ENTER to continue]
#
# [Collection in HTTP mode - 3s timeout for request/response]
# [Wait ~5 minutes for 40,000 HTTP (Hash) samples]
#
# [In Mininet - JSON variant]
# > py [net.get(f'h{i}').cmd('python3 attack/http_flood.py http://10.0.0.10:8000 json &') for i in range(11, 15)]
# > [Press ENTER to continue]
#
# [Collection continues in HTTP mode]
# [Wait ~5 minutes for 40,000 HTTP (JSON) samples]

# ============= PHASE 4: SLOWLORIS =============
# [PHASE 4️⃣ ] SLOWLORIS ATTACK - 10 min
# [💡] Slowloris: Slow header transmission, bắt long-lived connections
# [*] Tuning: Long timeouts (ACTIVE=30s, IDLE=15s)
# [MARKER] Created .marker_slowloris for phase 4
#
# [In Mininet]
# > py [net.get(f'h{i}').cmd('python3 attack/slowloris.py http://10.0.0.11:8000 &') for i in range(16, 21)]
# > [Press ENTER to continue]
#
# [Collection in Slowloris mode - 15s timeout for slow connections]
# [Uses separate FIFO: zeek_stream_slowloris.json]
# [Wait ~10 minutes for 80,000 Slowloris samples]

# ============= COLLECTION COMPLETE =============
# 🎉 THÀNH CÔNG! Dataset 5 lớp đã sẵn sàng tại master_dataset_v7.csv
# [*] Tổng số mẫu dự kiến: 520,000
```

---

## Monitoring During Collection

### Terminal 3: Track Progress
```bash
# Watch file size growing
watch -n 5 'wc -l /home/tgf/Documents/DoAn_SDN/thuThapData/master_dataset_v7.csv && du -h /home/tgf/Documents/DoAn_SDN/thuThapData/master_dataset_v7.csv'

# Expected growth:
# After Phase 0 (50 min):   200,001 lines (headers + 200k samples)
# After Phase 1 (10 min):   280,001 lines
# After Phase 2 (10 min):   360,001 lines
# After Phase 3 (10 min):   440,001 lines
# After Phase 4 (10 min):   520,001 lines

# Approximate file sizes:
# Phase 0: 50 MB (200k samples)
# Phase 1: 20 MB (80k samples)
# Phase 2: 20 MB (80k samples)
# Phase 3: 20 MB (80k samples)
# Phase 4: 20 MB (80k samples)
# Total: 130 MB
```

### Terminal 4: Monitor Timeout Profile Changes
```bash
# Watch batPack_v2 logs for phase detection
tail -f /home/tgf/Documents/DoAn_SDN/logs/batpack_v2.log | grep -E "PROFILE|PHASE|Created|deleted"

# Expected output pattern:
# [PROFILE] Phase=NORMAL: Normal: Standard bidirectional flows
# [PROFILE] Using timeouts: ACTIVE=10s, IDLE=5s
# [STREAM] Starting on interface: s6-eth1
# 
# [After 50 min - Phase 1 starts]
# [PROFILE] Phase=UDP: UDP Flood: Fast flow closure (unidirectional)
# [PROFILE] Using timeouts: ACTIVE=3s, IDLE=1s
# [STREAM] Starting on interface: s6-eth1
#
# [After 10 min - Phase 2 starts]
# [PROFILE] Phase=SYN: SYN Flood: Capture half-open connections
# [PROFILE] Using timeouts: ACTIVE=5s, IDLE=2s
# ...
```

### Terminal 5: Check Marker Creation/Deletion
```bash
# Watch marker files (they are created and removed per phase)
watch -n 3 'ls -la /home/tgf/Documents/DoAn_SDN/ai/.marker_* 2>/dev/null | awk "{print \$NF, \"(\" \$6, \$7, \$8 \")\"}" || echo "No markers currently active"'

# Expected pattern:
# .marker_normal (created at start of Phase 0, deleted when done)
# [pause]
# .marker_udp (created at start of Phase 1, deleted when done)
# [pause]
# .marker_syn (created at start of Phase 2, deleted when done)
# [pause]
# .marker_http (created at start of Phase 3, deleted when done)
# [pause]
# .marker_slowloris (created at start of Phase 4, deleted when done)
```

---

## Post-Collection Verification

Once all phases complete (~90 minutes):

### Step 1: Verify Dataset Size
```bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData

# Count total lines
wc -l master_dataset_v7.csv
# Expected: 520,001 (header + 520,000 data rows)

# Check file size
du -h master_dataset_v7.csv
# Expected: ~130 MB
```

### Step 2: Verify Label Distribution
```python
cd /home/tgf/Documents/DoAn_SDN

python3 << 'EOF'
import pandas as pd

df = pd.read_csv('thuThapData/master_dataset_v7.csv')

print("Dataset Statistics:")
print(f"Total rows: {len(df):,}")
print(f"\nLabel Distribution:")
label_counts = df['target_label'].value_counts().sort_index()
labels = {0: "Normal", 1: "UDP", 2: "SYN", 3: "HTTP", 4: "Slowloris"}
for label_id, count in label_counts.items():
    pct = 100 * count / len(df)
    print(f"  {labels.get(label_id, f'Label {label_id}'):<12}: {count:>7,} samples ({pct:>5.1f}%)")

print(f"\nFeature Columns ({len(df.columns)-1}):")
for col in list(df.columns[:-1]):
    print(f"  - {col}")

print(f"\nTarget Column: {df.columns[-1]}")

# Quick quality check
print("\nData Quality Checks:")
print(f"  Missing values: {df.isnull().sum().sum()}")
print(f"  Data types OK: {all(df.dtypes != 'object')}")
print(f"  All rows have 14 columns: {len(df.columns) == 14}")
EOF
```

Expected output:
```
Dataset Statistics:
Total rows: 520,000

Label Distribution:
  Normal          : 200,000 samples (38.5%)
  UDP             :  80,000 samples (15.4%)
  SYN             :  80,000 samples (15.4%)
  HTTP            :  80,000 samples (15.4%)
  Slowloris       :  80,000 samples (15.4%)

Feature Columns (13):
  - Src_Port
  - Dst_Port
  - Protocol
  ... (and 10 more)

Target Column: target_label

Data Quality Checks:
  Missing values: 0
  Data types OK: True
  All rows have 14 columns: True
```

### Step 3: Run Comprehensive Data Validation
```bash
cd /home/tgf/Documents/DoAn_SDN

python3 ai/check_data.py

# Expected outputs:
# ✅ Data shape and types verified
# ✅ No NaN/Inf values
# ✅ Scale check passed
# ✅ Duplicates: 0
# ✅ Class balance: Good ratio (2.5:1 between Normal and attacks)
# ✅ Feature distribution analyzed
# ✅ Outliers detected: X rows with Z-score > 3
# ✅ Output: dataset_v7_report.png
```

---

## Troubleshooting During Collection

### Issue: "No marker found, waiting for generator signal..."
**In Terminal 1 (batPack_v2):**
- This is normal - waiting for data collection to start
- Will change to `[PROFILE] Phase=NORMAL...` when collection begins

### Issue: "FIFO permission denied"
**Solution:**
```bash
# Ensure batPack_v2 runs with sudo
# Also ensure FIFO created with mode 0o666
ls -la ai/zeek_stream.json
# Should show: -rw-rw-rw-

# If permissions wrong:
sudo rm ai/zeek_stream*.json
sudo python3 ai/batPack_v2.py  # Recreates with correct permissions
```

### Issue: Collection seems stuck (not collecting flows)
**Check:**
```bash
# Verify flows are being generated
sudo nfstream -i s6-eth1 -c 10 | tail -5

# Check if FIFO is blocked
lsof | grep zeek_stream

# Check batPack_v2 logs for errors
tail -50 logs/batpack_v2.log | grep -i error
```

### Issue: Lower than expected sample count
**May be due to filtering:**
```bash
# Check how many flows are being dropped
tail -20 thuThapData/master_dataset_v7.csv  # Shows filter stats in console

# Debug: Enable DEBUG_MODE in auto_dataset_generator.py
# Edit: SMART_SUBNET_FILTER or DEBUG_MODE flags
```

---

## Timeline

```
Start Collection:
00:00 - 50:00  Phase 0: Normal traffic         (200k samples)
50:00 - 60:00  Phase 1: UDP Flood             (80k samples)
60:00 - 70:00  Phase 2: SYN Flood             (80k samples)
70:00 - 75:00  Phase 3: HTTP Flood (Hash)     (40k samples)
75:00 - 80:00  Phase 3: HTTP Flood (JSON)     (40k samples)
80:00 - 90:00  Phase 4: Slowloris            (80k samples)
─────────────────────────────────────────────
90:00 - ✅ Complete! 520,000 samples collected
```

---

## What to Do After Collection

### 1. Validate Dataset
```bash
python3 ai/check_data.py
# Generates: dataset_v7_report.png (distribution plots)
```

### 2. Upload to Cloud (for training)
```bash
# Option A: Google Colab
# Upload master_dataset_v7.csv to Google Drive
# Run: ai/train_colab_v2.py in Colab

# Option B: Local training
pip install torch scikit-learn
python3 ai/train_colab_v2.py --input thuThapData/master_dataset_v7.csv
```

### 3. Deploy IDS
```bash
# Copy trained models
cp ai/sdn_model_*.pth ai/
cp ai/sdn_autoencoder.pth ai/

# Start real-time IDS
python3 ai/run_onos_v2.py

# Configure ONOS integration
export ONOS_URL="http://172.17.0.2:8181"
export ONOS_AUTH="onos:rocks"
```

---

## Quick Reference Commands

```bash
# All-in-one check
python3 -c "
import pandas as pd
import os
df = pd.read_csv('thuThapData/master_dataset_v7.csv')
print('✅ Rows:', len(df))
print('✅ Label dist:', dict(df['target_label'].value_counts().sort_index()))
print('✅ Size:', os.path.getsize('thuThapData/master_dataset_v7.csv') / 1024 / 1024, 'MB')
"

# Monitor everything at once
# In separate terminals:
tail -f logs/batpack_v2.log | grep PROFILE  # Terminal 3
watch -n 5 'wc -l thuThapData/master_dataset_v7.csv'  # Terminal 4
watch -n 2 'ls -la ai/.marker_* 2>/dev/null || echo waiting'  # Terminal 5
```

---

**Status**: ✅ Ready for Execution  
**Estimated Duration**: 90-100 minutes  
**Final Output**: `thuThapData/master_dataset_v7.csv` (520,000 samples)
