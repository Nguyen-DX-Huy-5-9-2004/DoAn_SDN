# 📊 TỐI ƯU COLLECTION STRATEGY - DATA COLLECTION V6

## 🎯 Mục tiêu

- **400,000 samples** (80K mỗi class) cho training
- **3 giờ** thời gian tổng (thay vì 13+ giờ)
- **Highest quality dataset** - bidirectional flows, optimal interface

---

## 🏗️ TOPOLOGY RECAP

```
Clients (h60-h65)          Botnet (h1-h20)
    ↓ (s3)                    ↓ (s2)
    └─── s1 (CORE) ───┘
         ↓ (s1-eth1)
    s6 (Web Switch)
    ↓ (s6-eth1) ← 🎯 CAPTURE HERE
    
    Flows: REQUEST → web1 (10.0.0.10:8000)
           RESPONSE ← web1 (10.0.0.10:8000)
```

---

## ✅ FIX APPLIED

| Vấn đề | Trước | Sau | Cải tiến |
|--------|-------|-----|---------|
| Capture interface | s6-eth5 (Docker) | **s6-eth1** (backbone) | 3-13x faster |
| Filter logic | Chỉ REQUEST | REQUEST + RESPONSE | +50% flows |
| Collection order | NORMAL→ATTACK | **ATTACK→NORMAL** | Flexible timing |
| Clients | Không rõ | h60-h65 (6 nodes) | Accurate topology |

---

## 📋 PHASES (Thứ tự tối ưu)

### PHASE 1: UDP Flood (10 min)
```
Hosts:  h1-h4 (4 nodes)
Attack: UDP flood → 10.0.0.10:8000
Target: 80,000 samples
Speed:  ~8,000 samples/min
```

### PHASE 2: SYN Flood (10 min)
```
Hosts:  h6-h10 (5 nodes)
Attack: SYN flood → 10.0.0.10:8000
Target: 80,000 samples
Speed:  ~8,000 samples/min
```

### PHASE 3: HTTP Flood (10 min)
```
Hosts:  h11-h14 (4 nodes)
Attack: HTTP flood → 10.0.0.10:8000
Target: 80,000 samples
Speed:  ~8,000 samples/min
```

### PHASE 4: Slowloris (10 min)
```
Hosts:  h16-h20 (5 nodes)
Attack: Slowloris → 10.0.0.10:8000
Target: 80,000 samples
Speed:  ~8,000 samples/min
```

### PHASE 0: Normal Traffic (50 min)
```
Hosts:  h60-h65 (6 nodes)
Traffic: Normal HTTP requests → 10.0.0.10:8000
Target: 80,000 samples
Speed:  ~1,600 samples/min (slower but acceptable)
```

---

## 🖥️ TERMINAL SETUP (3 terminals)

### Terminal 1: Packet Capture (batPack123.py)

```bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 batPack123.py
```

**Expected output:**
```
[INFO] Connecting to IPC: zeek_stream.json
[INFO] Using interface: s6-eth1 (backbone, optimal)
[INFO] Capturing packets...
[+] Received packet: 2024-04-18 10:00:00 | 583 flows | ...
```

---

### Terminal 2: Flow Processing (auto_dataset_generator.py)

```bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 auto_dataset_generator.py
```

**Expected output:**
```
[INFO] Watching zeek_stream.json for flows...
[PHASE 1: UDP Flood] Processing flows...
[STATS] 10:00-10:10 | Flows: 83,000 | Pass: 82,500 (99.4%)
[CSV] master_dataset_v6.csv: 82,500 rows

[PHASE 2: SYN Flood] Processing flows...
[STATS] 10:10-10:20 | Flows: 82,000 | Pass: 81,600 (99.5%)
[CSV] master_dataset_v6.csv: 164,100 rows
...
```

---

### Terminal 3: Mininet Commands

Run in Mininet CLI (`containernet>`)

---

## 🚀 EXECUTION GUIDE

### Bước 1: Chạy 2 terminals capture/generator

**Terminal 1:** `sudo python3 batPack123.py`  
**Terminal 2:** `sudo python3 auto_dataset_generator.py`

---

### Bước 2: PHASE 1 - UDP Flood (10 min)

**Mininet CMD:**
```
containernet> py [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(1, 21)] + [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(60, 66)]
# Wait 2 seconds
containernet> py [net.get(f'h{i}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 attack/udp_flood.py 10.0.0.10 &') for i in range(1, 5)]
```

**Monitor Terminal 2:** Watch for ~80K samples over 10 minutes  
**Expected speed:** ~8,000 samples/min

⏱️ **Wait 10 minutes**, then proceed to Phase 2

---

### Bước 3: PHASE 2 - SYN Flood (10 min)

**Mininet CMD:**
```
containernet> py [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(1, 21)] + [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(60, 66)]
# Wait 2 seconds
containernet> py [net.get(f'h{i}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 attack/syn_flood.py 10.0.0.10 &') for i in range(6, 11)]
```

**Monitor Terminal 2:** Watch for next ~80K samples  
**Expected cumulative:** ~160K samples

⏱️ **Wait 10 minutes**, then proceed to Phase 3

---

### Bước 4: PHASE 3 - HTTP Flood (10 min)

**Mininet CMD:**
```
containernet> py [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(1, 21)] + [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(60, 66)]
# Wait 2 seconds
containernet> py [net.get(f'h{i}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 attack/http_flood.py 10.0.0.10 &') for i in range(11, 15)]
```

**Monitor Terminal 2:** Watch for next ~80K samples  
**Expected cumulative:** ~240K samples

⏱️ **Wait 10 minutes**, then proceed to Phase 4

---

### Bước 5: PHASE 4 - Slowloris (10 min)

**Mininet CMD:**
```
containernet> py [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(1, 21)] + [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(60, 66)]
# Wait 2 seconds
containernet> py [net.get(f'h{i}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 attack/slowloris.py 10.0.0.10 &') for i in range(16, 21)]
```

**Monitor Terminal 2:** Watch for next ~80K samples  
**Expected cumulative:** ~320K samples

⏱️ **Wait 10 minutes**, then proceed to Phase 0

---

### Bước 6: PHASE 0 - Normal Traffic (50 min)

**Mininet CMD:**
```
containernet> py [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(1, 21)] + [net.get(f'h{i}').cmd('pkill -f attack/ traffic/') for i in range(60, 66)]
# Wait 2 seconds
containernet> py [net.get(f'h{i}').cmd('cd /home/tgf/Documents/DoAn_SDN && python3 traffic/normal.py http://10.0.0.10:8000 &') for i in range(60, 66)]
```

**Monitor Terminal 2:** Watch for next ~80K samples  
**Expected cumulative:** ~400K samples ✅

⏱️ **Wait 50 minutes for completion**

---

## ✅ VALIDATION CHECKLIST

After all phases complete:

```bash
# Terminal bash
cd /home/tgf/Documents/DoAn_SDN/thuThapData
wc -l master_dataset_v6.csv
```

**Expected output:**
```
400001 master_dataset_v6.csv
↓
400,000 rows + 1 header = 400,001 lines ✅
```

**CSV validation:**
```python
import pandas as pd
df = pd.read_csv('master_dataset_v6.csv')

print(f"Rows: {len(df)}")        # 400,000
print(f"Cols: {len(df.columns)}") # 14
print(df['label'].value_counts())
# Expected: 80K each (Normal, UDP Flood, SYN Flood, HTTP Flood, Slowloris)
```

---

## 📊 EXPECTED RESULTS

| Metric | Target | Expected |
|--------|--------|----------|
| **Total samples** | 400K | 400K ✅ |
| **Classes** | 5 | Normal + 4 attacks ✅ |
| **Samples/class** | 80K | ~80K each ✅ |
| **Collection time** | <3 hours | ~40 min (attacks) + 50 min (normal) = 90 min ✅ |
| **Filter pass rate** | 95%+ | 99%+ (bidirectional) ✅ |
| **Flow quality** | Complete | REQUEST + RESPONSE ✅ |

---

## 🔧 TROUBLESHOOTING

### Problem: "Not all samples collected"

**Solution:** Check Terminal 2 output for rejection reasons
```bash
# In Terminal 2, look for:
REJECTED: NOT_WEB_TRAFFIC (← Response flows with wrong port)
REJECTED: SYSTEM_HOST (← IDS/monitoring traffic)
```

### Problem: "s6-eth1 not available"

**Solution:** Update batPack123.py to try alternatives:
```python
preferred = ["s6-eth1", "s6-eth4", "s6-eth3", "eth1"]  # Try in order
```

### Problem: "Slow collection speed"

**Check:**
- Is batPack123.py running? (should see flow logs)
- Is auto_dataset_generator.py processing? (should see CSV updates)
- Check network: `containernet> py net.links()`

---

## 📝 NOTES

1. **Bidirectional filter now active** - Captures both REQUEST and RESPONSE flows
2. **Optimal interface s6-eth1** - Backbone between s1 and s6
3. **Attack phases first** - Allow flexible timing for normal phase
4. **6 clients for normal** - h60-h65 as per topology

---

## 🎓 WHAT'S DIFFERENT FROM BEFORE?

```
OLD STRATEGY:
  ❌ Capture on s6-eth5 (Docker bridge)
  ❌ Unidirectional filter (request only)
  ❌ Normal phase first
  ❌ Unknown hosts (guessed h66-h74)
  
NEW STRATEGY:
  ✅ Capture on s6-eth1 (backbone)
  ✅ Bidirectional filter (request + response)
  ✅ Attack phases first (Phase 1-4, then 0)
  ✅ Verified topology (h1-20 botnet, h60-65 clients)
```

---

**Next Step:** Run the orchestrator to see full instructions!

```bash
python3 /home/tgf/Documents/DoAn_SDN/data_collection_orchestrator.py
```

