# 🚀 Data Collection Optimization - Quick Summary

## What Changed?

### 1. Phase Order (Normal First) ✅
```
BEFORE: UDP → SYN → HTTP → Normal → Slowloris
AFTER:  Normal → UDP → SYN → HTTP → Slowloris
```

**Why?** Normal traffic doesn't need any attacks running, so collect it first with clean network state.

---

## 2. Attack-Specific Timeout Tuning ✅

Each attack now has unique NFStreamer timeouts matched to its characteristics:

| Attack | Old Timeout | New Timeout | Reason |
|--------|---|---|---|
| **Normal** | ACTIVE=10s, IDLE=5s | Same | Baseline - no change |
| **UDP Flood** | ACTIVE=10s, IDLE=5s | ACTIVE=3s, IDLE=1s | One-way packets, no response |
| **SYN Flood** | ACTIVE=10s, IDLE=5s | ACTIVE=5s, IDLE=2s | Half-open, incomplete handshakes |
| **HTTP Flood** | ACTIVE=10s, IDLE=5s | ACTIVE=8s, IDLE=3s | Sustained connections, pooling |
| **Slowloris** | ACTIVE=10s, IDLE=5s | ACTIVE=30s, IDLE=15s | Slow transmission, keep-alive |

---

## 3. Granular Phase Markers ✅

Added specific marker files for each phase:
- `.marker_normal` → Normal traffic
- `.marker_udp` → UDP Flood
- `.marker_syn` → SYN Flood  
- `.marker_http` → HTTP Flood
- `.marker_slowloris` → Slowloris

**Why?** Allows `batPack_v2.py` to automatically detect which attack is running and apply correct timeouts.

---

## Files Modified

### ✅ `thuThapData/auto_dataset_generator.py`

**New Functions:**
```python
create_phase_marker(label_id)   # Create marker for current phase
cleanup_all_markers()            # Remove all markers
```

**Updated main():**
- Reordered phases: Normal (phase 0) now runs first
- Each phase calls `create_phase_marker()` instead of manual marker creation
- Each phase calls `cleanup_all_markers()` when done
- Added descriptions of each attack's characteristics

### ✅ `ai/batPack_v2.py`

**New Configuration:**
```python
TIMEOUT_PROFILES = {
    "NORMAL": {"ACTIVE_TIMEOUT": 10, "IDLE_TIMEOUT": 5},
    "UDP": {"ACTIVE_TIMEOUT": 3, "IDLE_TIMEOUT": 1},
    "SYN": {"ACTIVE_TIMEOUT": 5, "IDLE_TIMEOUT": 2},
    "HTTP": {"ACTIVE_TIMEOUT": 8, "IDLE_TIMEOUT": 3},
    "SLOWLORIS": {"ACTIVE_TIMEOUT": 30, "IDLE_TIMEOUT": 15}
}
```

**Enhanced Functions:**
- `BatPackConfig.get_profile()` - Auto-detect phase from markers
- `choose_fifo_mode()` - Returns phase-specific timeout profile
- `_stream_flows_generator()` - Uses dynamic timeouts per phase

---

## Benefits

1. **✅ Cleaner Normal Data**
   - Collected first with no attack interference
   - Better baseline for model training

2. **✅ Attack-Specific Accuracy**
   - UDP: Fast collection (1s timeout)
   - SYN: Half-open capture (2s timeout)
   - HTTP: Sustained load (3s timeout)
   - Slowloris: Slow attack (15s timeout)

3. **✅ Automatic Phase Tuning**
   - No manual configuration needed
   - Markers automatically detected
   - Timeouts applied dynamically

4. **✅ Production-Ready**
   - Works for both data collection and real-time IDS
   - Seamless integration with `run_onos_v2.py`
   - Backward compatible with existing FIFO structure

---

## Quick Start

```bash
# Terminal 1: Start batPack_v2 (automatic timeout switching)
cd /home/tgf/Documents/DoAn_SDN
sudo python3 ai/batPack_v2.py

# Terminal 2: Start optimized data collection
cd /home/tgf/Documents/DoAn_SDN/thuThapData
sudo python3 auto_dataset_generator.py

# Automatic execution order:
# Phase 0: Normal (200k samples) - ~50 min
# Phase 1: UDP (80k samples) - ~10 min
# Phase 2: SYN (80k samples) - ~10 min
# Phase 3: HTTP (80k samples) - ~10 min
# Phase 4: Slowloris (80k samples) - ~10 min
# Total: 520k samples - ~90 min
```

---

## Verification

Check that phases are detected correctly:
```bash
# Monitor batPack_v2 logging
tail -f logs/batpack_v2.log | grep PROFILE

# Expected output:
# [PROFILE] Phase=NORMAL: Normal: Standard bidirectional flows
# [PROFILE] Using timeouts: ACTIVE=10s, IDLE=5s
# [PROFILE] Phase=UDP: UDP Flood: Fast flow closure (unidirectional)
# [PROFILE] Using timeouts: ACTIVE=3s, IDLE=1s
# [PROFILE] Phase=SYN: SYN Flood: Capture half-open connections
# [PROFILE] Using timeouts: ACTIVE=5s, IDLE=2s
# ... and so on
```

---

## Data Quality Improvements

### Before
- Normal phase had attack residue
- All phases used same timeout (10s IDLE)
- May miss slow attacks like Slowloris
- May over-fragment fast attacks like UDP

### After ✅
- Normal phase is clean (first, no attacks)
- Each attack uses optimal timeout
- Slowloris: 15s IDLE captures slow patterns
- UDP: 1s IDLE avoids artificial merging
- SYN: 2s IDLE captures incomplete handshakes
- HTTP: 3s IDLE handles request pooling

---

## Dataset Output

Location: `thuThapData/master_dataset_v7.csv`

Expected distribution:
```
0 (Normal):     200,000 samples ✓
1 (UDP):         80,000 samples ✓
2 (SYN):         80,000 samples ✓
3 (HTTP):        80,000 samples ✓
4 (Slowloris):   80,000 samples ✓
─────────────────────────────
Total:          520,000 samples
```

Each sample: 13 features + label

---

## Advanced: Custom Tuning

If you need to adjust timeouts, edit the `TIMEOUT_PROFILES` in `ai/batPack_v2.py`:

```python
TIMEOUT_PROFILES = {
    "UDP": {
        "ACTIVE_TIMEOUT": 2,    # Faster closure if needed
        "IDLE_TIMEOUT": 0.5,    # More aggressive
        "desc": "UDP Flood: Fast flow closure"
    },
    # ... adjust others as needed
}
```

No changes needed to `auto_dataset_generator.py` - markers still work!

---

## Compatibility Notes

✅ **Backward Compatible**
- Still uses same FIFO paths
- Still produces 13 features per flow
- Still generates CSV format
- Works with existing `run_onos_v2.py`

✅ **Dual Purpose**
- Data collection: Full 520k dataset generation
- Demo mode: Real-time IDS with `run_onos_v2.py`

✅ **Extensible**
- Can add new attack profiles easily
- Can adjust timeouts per deployment
- Can add new phases without code changes

---

## Monitoring Commands

```bash
# Watch collection progress
watch -n 5 'tail -3 thuThapData/master_dataset_v7.csv && echo "---" && wc -l thuThapData/master_dataset_v7.csv'

# Monitor phase transitions
tail -f logs/batpack_v2.log | grep -E "PROFILE|PHASE"

# Check marker status
ls -la ai/.marker_* 2>/dev/null || echo "No phase marker active"
```

---

## Summary of Changes

```
auto_dataset_generator.py:
  + create_phase_marker(label_id) function
  + cleanup_all_markers() function
  + Reordered main(): Normal (0) before attacks (1-4)
  + Each phase now creates specific marker

ai/batPack_v2.py:
  + TIMEOUT_PROFILES configuration dictionary
  + Enhanced BatPackConfig.get_profile() method
  + Enhanced choose_fifo_mode() for granular markers
  + Updated _stream_flows_generator() with dynamic timeouts
```

---

**Status**: ✅ Complete and Ready for Production  
**Total Collection Time**: ~90 minutes  
**Dataset Size**: 520,000 samples  
**Data Quality**: Optimized with attack-specific tuning
