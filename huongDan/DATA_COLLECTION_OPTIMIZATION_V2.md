# 📊 Data Collection Optimization (Normal First + Attack-Specific Tuning)

## 1. Overview

Comprehensive optimization of data collection pipeline to:
1. **Collect Normal traffic first** (not last) - requires no attack infrastructure
2. **Attack-specific timeout tuning** - each attack has unique flow characteristics
3. **Dual-mode operation** - works for both production IDS demo and dataset generation
4. **Granular phase markers** - precise control over NFStreamer behavior per attack type

---

## 2. Phase Ordering Change

### OLD ORDER (Suboptimal)
```
Phase 1 → UDP Flood    (80k samples)
Phase 2 → SYN Flood    (80k samples)
Phase 3 → HTTP Flood   (80k samples)
Phase 4 → Normal       (200k samples) ← PROBLEM: Last, requires attack cleanup
Phase 5 → Slowloris    (80k samples)
```

### NEW ORDER (Optimized) ✅
```
Phase 0 → Normal       (200k samples) ← First, no attack infrastructure needed
   └─ No attack processes running
   └─ Pure bidirectional client↔server flows
   
Phase 1 → UDP Flood    (80k samples) ← Fast collection, unidirectional
Phase 2 → SYN Flood    (80k samples) ← Half-open connections
Phase 3 → HTTP Flood   (80k samples) ← Application-layer sustained load
Phase 4 → Slowloris    (80k samples) ← Long-lived slow connections
```

### Benefits
- **✅ Cleaner Normal data**: No risk of attack bleed-through into baseline
- **✅ Sequential infrastructure**: Minimal reconfiguration between phases
- **✅ Better dataset balance**: Normal collected at stable network state
- **✅ Attack containment**: Each attack starts with clean slate

---

## 3. Attack-Specific NFStreamer Tuning

Each attack type has unique characteristics requiring different flow timeout values:

### Normal Traffic Profile
```python
ACTIVE_TIMEOUT:  10s   # Bidirectional, normal keep-alive patterns
IDLE_TIMEOUT:    5s    # Standard network conversation
Phase Marker:    .marker_normal
Characteristic:  Proper TCP handshakes, varied packet rates, expected state transitions
```

**Why these values?**
- Normal user traffic has mixed request-response patterns
- Some connections are long-lived (HTTP keep-alive)
- Need to avoid fragmenting a single "flow session" into multiple NFStreamer flows

---

### UDP Flood Attack Profile
```python
ACTIVE_TIMEOUT:  3s    # Short - UDP is unidirectional
IDLE_TIMEOUT:    1s    # Very short - no response expected
Phase Marker:    .marker_udp
Characteristic:  One-way packets, no handshake, anomaly_score=1, extreme packet rates
```

**Why these values?**
- UDP sender doesn't wait for responses (no TCP ACK)
- Each UDP packet is essentially one-way
- Closing flows quickly avoids artificial connection merging
- High throughput → fast flow churn

---

### SYN Flood Attack Profile
```python
ACTIVE_TIMEOUT:  5s    # Medium - half-open connections
IDLE_TIMEOUT:    2s    # Short - incomplete handshakes timeout
Phase Marker:    .marker_syn
Characteristic:  SYN packets only, incomplete 3-way handshake, conn_state="SYN_SENT"
```

**Why these values?**
- SYN flood: attacker sends SYN but ignores SYN-ACK responses
- Half-open connections never complete (no DATA phase)
- Must close them relatively quickly to show attack pattern
- Intermediate timeout between UDP (short) and HTTP (longer)

---

### HTTP Flood Attack Profile
```python
ACTIVE_TIMEOUT:  8s    # Medium-long - HTTP request/response cycles
IDLE_TIMEOUT:    3s    # Moderate - wait for HTTP responses
Phase Marker:    .marker_http
Characteristic:  GET/POST requests on ports 80/443/8000, sustained connections, requests in bursts
```

**Why these values?**
- HTTP is request-response protocol
- Connection pooling → multiple requests per connection
- Keep-alive headers extend connection lifetime
- Need longer timeout than SYN but shorter than Slowloris

---

### Slowloris Attack Profile
```python
ACTIVE_TIMEOUT:  30s   # Very long - slow header transmission
IDLE_TIMEOUT:    15s   # Long - periodic keep-alive packets
Phase Marker:    .marker_slowloris
Characteristic:  Slow header transmission, extended idle periods, periodic keep-alive, separate FIFO
```

**Why these values?**
- Slowloris keeps connections alive intentionally
- Sends partial HTTP headers, waits, sends more
- Periodic keep-alive packets to prevent timeout
- Must capture full 15-30 second "attack session" as single flow
- Uses separate FIFO: `zeek_stream_slowloris.json`

---

## 4. Marker-Based Phase Detection

### New Granular Markers
```
ai/.marker_normal      → Normal traffic collection
ai/.marker_udp         → UDP Flood attack phase
ai/.marker_syn         → SYN Flood attack phase
ai/.marker_http        → HTTP Flood attack phase
ai/.marker_slowloris   → Slowloris attack phase
```

### Marker Lifecycle
```
auto_dataset_generator.py                batPack_v2.py
        │                                     │
        ├─ create_phase_marker(0)  ───→  .marker_normal created
        │  (start Normal collection)      batPack reads profile
        │                            
        ├─ cleanup_all_markers()   ───→  .marker_normal deleted
        │
        ├─ create_phase_marker(1)  ───→  .marker_udp created
        │  (start UDP collection)        batPack reads profile
        │
        └─ [repeat for SYN, HTTP, Slowloris]
```

### Detection in batPack_v2
```python
def choose_fifo_mode():
    """Priority order for marker detection"""
    if .marker_slowloris:        # Highest priority
        return SLOWLORIS_PROFILE
    elif .marker_http:
        return HTTP_PROFILE
    elif .marker_syn:
        return SYN_PROFILE
    elif .marker_udp:
        return UDP_PROFILE
    elif .marker_normal:
        return NORMAL_PROFILE
    else:
        return NORMAL_PROFILE     # Default for real-time IDS
```

---

## 5. Implementation Details

### auto_dataset_generator.py Changes

**New Functions:**
```python
def create_phase_marker(label_id):
    """
    Create phase-specific marker for batPack_v2 timeout tuning
    Removes all old markers before creating new one
    
    Args:
        label_id: 0=Normal, 1=UDP, 2=SYN, 3=HTTP, 4=Slowloris
    """

def cleanup_all_markers():
    """Remove all phase markers"""
```

**Updated main():**
```python
# PHASE 0: Normal (NEW - FIRST)
print("[PHASE 0️⃣ ] NORMAL TRAFFIC - 50 min (FIRST)")
create_phase_marker(0)        # Creates .marker_normal
collect_data(0, target_samples=NORMAL_SAMPLES_TARGET)
cleanup_all_markers()         # Removes .marker_normal

# PHASE 1: UDP Flood
print("[PHASE 1️⃣ ] UDP FLOOD ATTACK - 10 min")
create_phase_marker(1)        # Creates .marker_udp
collect_data(1, target_samples=TARGET_SAMPLES_PER_CLASS)
cleanup_all_markers()         # Removes .marker_udp

# PHASE 2-4: Similar pattern for SYN, HTTP, Slowloris
```

---

### batPack_v2.py Changes

**Enhanced Configuration:**
```python
class BatPackConfig:
    TIMEOUT_PROFILES = {
        "NORMAL": {
            "ACTIVE_TIMEOUT": 10,
            "IDLE_TIMEOUT": 5,
            "desc": "Normal: Standard bidirectional flows"
        },
        "UDP": {
            "ACTIVE_TIMEOUT": 3,
            "IDLE_TIMEOUT": 1,
            "desc": "UDP Flood: Fast flow closure (unidirectional)"
        },
        "SYN": {
            "ACTIVE_TIMEOUT": 5,
            "IDLE_TIMEOUT": 2,
            "desc": "SYN Flood: Capture half-open connections"
        },
        "HTTP": {
            "ACTIVE_TIMEOUT": 8,
            "IDLE_TIMEOUT": 3,
            "desc": "HTTP Flood: Sustained HTTP requests"
        },
        "SLOWLORIS": {
            "ACTIVE_TIMEOUT": 30,
            "IDLE_TIMEOUT": 15,
            "desc": "Slowloris: Long-lived slow connections"
        }
    }
    
    @classmethod
    def get_profile(cls):
        """Auto-detect current phase and return profile"""
        # Checks markers in priority order
        # Returns appropriate ACTIVE_TIMEOUT and IDLE_TIMEOUT
```

**Enhanced Flow Streaming:**
```python
def _stream_flows_generator(self, fifo_handle):
    # Get current timeout profile based on markers
    mode, _, profile = choose_fifo_mode()
    active_timeout = profile["ACTIVE_TIMEOUT"]
    idle_timeout = profile["IDLE_TIMEOUT"]
    
    # Initialize NFStreamer with phase-specific timeouts
    streamer = NFStreamer(
        source=self.iface,
        active_timeout=active_timeout,
        idle_timeout=idle_timeout,
        statistical_analysis=True
    )
    
    # Detect phase transitions and restart if markers change
    for flow in streamer:
        if marker_changed():
            break  # Restart with new profile
```

---

## 6. Data Quality Impact

### Before Optimization
```
Normal Phase (Last):
├─ May contain attack residue from cleanup
├─ Network state may be stressed
└─ Baseline data less representative

Attack Phase:
└─ Each starts with potentially different network state
```

### After Optimization
```
Normal Phase (First):
├─ Pristine network state
├─ No attack residue
└─ Pure baseline data for model pre-training

Attack Phases:
├─ UDP: Short timeouts → capture fast one-way attacks
├─ SYN: Medium timeouts → capture incomplete handshakes
├─ HTTP: Moderate timeouts → capture sustained HTTP floods
└─ Slowloris: Long timeouts → capture slow kill attacks
```

---

## 7. Running the Optimized Collection

### Prerequisites
```bash
# Activate Python environment
source sdn_env/bin/activate

# Ensure NFStreamer and requests are installed
pip install nfstream requests

# Ensure markers directory exists
mkdir -p ai/
```

### Execution
```bash
# Terminal 1: Start batPack_v2 (continuous monitoring)
cd /home/tgf/Documents/DoAn_SDN
sudo python3 ai/batPack_v2.py

# Terminal 2: Start data collection with new phase ordering
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 auto_dataset_generator.py

# Output
# ✅ Phase 0: 200k Normal samples in ~50 min
# ✅ Phase 1: 80k UDP samples in ~10 min
# ✅ Phase 2: 80k SYN samples in ~10 min
# ✅ Phase 3: 80k HTTP samples in ~10 min
# ✅ Phase 4: 80k Slowloris samples in ~10 min
# 
# Total: 520k samples collected with attack-specific tuning
```

---

## 8. Verification Checklist

Before starting collection:
- [ ] Mininet topology running with containernet
- [ ] batPack_v2.py logging to logs/batpack_v2.log
- [ ] auto_dataset_generator.py output_csv configured
- [ ] Interface detection: s6-eth1 preferred (99.7% filter pass)
- [ ] Markers directory: `ai/` exists
- [ ] Web servers ready: web1 can run Django app

During collection:
- [ ] batPack_v2 logs show phase detection (UDP/SYN/HTTP/Slowloris)
- [ ] NFStreamer timeouts match expected profile
- [ ] Flow collection rate reasonable (~500-1000 flows/sec)
- [ ] No "FIFO permission denied" errors

After collection:
- [ ] master_dataset_v7.csv has 520k rows
- [ ] Label distribution: 200k (Normal), 80k×4 (Attacks)
- [ ] All 13 features present per flow
- [ ] No rows with missing anomaly_score

```bash
# Quick validation
python3 -c "
import pandas as pd
df = pd.read_csv('master_dataset_v7.csv')
print(f'Total rows: {len(df):,}')
print(f'Label distribution:\n{df[\"target_label\"].value_counts().sort_index()}')
print(f'Features: {list(df.columns[:-1])}')
"
```

---

## 9. Attack Characteristics vs NFStreamer Tuning

| Attack | Characteristic | Issue | Timeout Tuning |
|--------|---|---|---|
| **Normal** | Bidirectional, varied patterns | Keep-alive fragments flows | ACTIVE=10s, IDLE=5s |
| **UDP** | One-way, high rate, no handshake | Fast churn, unidirectional | ACTIVE=3s, IDLE=1s ✓ |
| **SYN** | Half-open, SYN only, no ACK | Incomplete handshakes | ACTIVE=5s, IDLE=2s ✓ |
| **HTTP** | Request-response, pooling | Sustained connections, multi-request | ACTIVE=8s, IDLE=3s ✓ |
| **Slowloris** | Slow headers, keep-alive, periodic | Intentional slow transmission | ACTIVE=30s, IDLE=15s ✓ |

---

## 10. Performance Metrics

### Collection Time Estimates
```
Phase 0 (Normal):       50 min  (200k samples ÷ 66 clients)
Phase 1 (UDP):          10 min  (80k samples ÷ 4 attackers)
Phase 2 (SYN):          10 min  (80k samples ÷ 5 attackers)
Phase 3 (HTTP Hash):     5 min  (40k samples ÷ 4 attackers)
Phase 3 (HTTP JSON):     5 min  (40k samples ÷ 4 attackers)
Phase 4 (Slowloris):    10 min  (80k samples ÷ 5 attackers)
─────────────────────────────
Total:                ~90 min  (520k total samples)
```

### Network Stats
```
batPack_v2 collection rate:  500-1000 flows/second
Flow features extracted:     13 per flow
Feature vector dimension:    26 (after differential features)
CSV write batch:             1000 rows
FIFO flush interval:         1 second
NFStreamer batch size:       50 flows
```

---

## 11. Troubleshooting

### Issue: "Marker not detected"
```
Solution: Ensure auto_dataset_generator creates markers correctly
Check: sudo ls -la ai/.marker_*
Fix: Verify auto_dataset_generator.py create_phase_marker() is called
```

### Issue: "FIFO permission denied"
```
Solution: Ensure batPack_v2 runs with sudo
Also: FIFO created with mode 0o666 for read/write access
```

### Issue: "Timeout profile not applied"
```
Solution: Check batPack_v2 logs for profile detection
Command: tail -f logs/batpack_v2.log | grep PROFILE
Expected: "[PROFILE] Phase=UDP: UDP Flood: Fast flow closure..."
```

### Issue: "Flow count lower than expected"
```
Solution: May be filtered by SMART_SUBNET_FILTER
Check: grep "dropped_by_subnet" master_dataset_v7.csv  
Debug: Enable DEBUG_MODE in auto_dataset_generator
```

---

## 12. Next Steps

After optimized collection completes:

1. **Validation**
   ```bash
   python3 ai/check_data.py
   # Produces: dataset_v7_report.png with distribution plots
   ```

2. **Training**
   ```bash
   # Upload dataset_v7.csv to Google Colab
   # Run: ai/train_colab_v2.py
   # Models: Autoencoder + CNN-GRU-Attention classifier
   # Output: sdn_model_*.pth, sdn_autoencoder.pth
   ```

3. **Deployment**
   ```bash
   # Copy models to production
   # Run: python3 run_onos_v2.py
   # Real-time IDS with SDN integration
   ```

---

## 13. Key Files Modified

```
✅ thuThapData/auto_dataset_generator.py
   ├─ Added: create_phase_marker(label_id)
   ├─ Added: cleanup_all_markers()
   └─ Changed: main() phase ordering (Normal first)

✅ ai/batPack_v2.py
   ├─ Added: TIMEOUT_PROFILES dictionary
   ├─ Enhanced: BatPackConfig.get_profile()
   ├─ Enhanced: choose_fifo_mode() with granular markers
   └─ Updated: _stream_flows_generator() to use profiles
```

---

## 14. Quick Reference

### Phase Markers
```bash
# View current phase
ls -la ai/.marker_* 2>/dev/null || echo "No phase active"

# Manual phase setup (for debugging)
touch ai/.marker_normal      # Start normal phase
touch ai/.marker_udp         # Start UDP phase
touch ai/.marker_slowloris   # Start Slowloris phase
rm ai/.marker_*              # Cleanup
```

### Monitoring
```bash
# Terminal 1: Monitor batPack_v2
tail -f logs/batpack_v2.log

# Terminal 2: Monitor auto_dataset_generator
tail -f thuThapData/master_dataset_v7.csv | tail -20

# Terminal 3: Check collection progress
watch -n 5 'wc -l thuThapData/master_dataset_v7.csv'
```

### Quick Check
```python
import pandas as pd
df = pd.read_csv('thuThapData/master_dataset_v7.csv')
print(df['target_label'].value_counts().sort_index())
# Expected:
# 0    200000  (Normal)
# 1     80000  (UDP)
# 2     80000  (SYN)
# 3     80000  (HTTP)
# 4     80000  (Slowloris)
```

---

**Author**: GitHub Copilot  
**Date**: 2026-04-23  
**Status**: ✅ COMPLETE - Ready for Production Data Collection
