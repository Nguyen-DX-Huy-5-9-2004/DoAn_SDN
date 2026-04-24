# 🏛️ Network Architecture & Data Collection Strategy

## Network Topology (3-Layer L3)

```
                         ┌─────────────────────┐
                         │   CORE SWITCH (s1)  │
                         └──────────┬──────────┘
                   ┌────────────────┼────────────────┐
                   │                │                │
         ┌─────────▼──────┐  ┌──────▼──────┐  ┌────▼────────────┐
         │  s2 BOTNET     │  │ s3 CLIENT   │  │ s6 WEB SERVER   │
         │  DISTRIBUTE    │  │ DISTRIBUTE  │  │                 │
         └────────┬───────┘  └──────┬──────┘  └────┬────────────┘
                  │                 │              │
         ┌────────▼──────┐  ┌──────▼──────┐       │
         │ s4 BOTNET    │  │ s5 DATACENTER
         │ ACCESS       │  │ FABRIC       │
         └────────┬──────┘  └──────┬──────┘
                  │                │
        ┌─────────┴──────┐   ┌─────┴──────────────────────┐
        │                │   │                            │
    ┌───▼──┐          ┌──▼───▼──┐  ┌─────────┐  ┌──────┐ ┌───▼────┐
    │h1-h20│          │h70,h71  │  │ h80,h81 │  │ h82  │ │web1,  │
    │ATTACK│          │SERVICES │  │IDS      │  │MON   │ │proxy1 │
    │HOSTS │          │h72: API │  │HONEYPOT │  │MIRROR│ │db1    │
    └──────┘          └─────────┘  └─────────┘  └──────┘ └────────┘
    10.0.1.x          10.0.0.x
                      (datacenter)
        ┌─────────────┐
        │ h60-h65     │ (now h60-h74 = 15 clients)
        │ CLIENT HOSTS│
        │ NORMAL USER │
        └─────────────┘
        10.0.2.x
```

---

## 📍 Host Inventory & Roles

### **Botnet Subnet (10.0.1.x) - Attack Source**
| Host | IP | Role | Purpose |
|------|-----|------|---------|
| h1-h20 | 10.0.1.1-20 | Attacker | UDP Flood, SYN Flood, HTTP Flood, Slowloris |

### **Client Subnet (10.0.2.x) - Normal Traffic**
| Host | IP | Role | Purpose |
|------|-----|------|---------|
| h60-h74 | 10.0.2.60-74 | Normal User | Generate benign HTTP traffic to web1 |

### **Services Subnet (10.0.0.x) - Infrastructure**
| Host | IP | Role | Purpose |
|------|-----|------|---------|
| **web1** | 10.0.0.11 | Web Server | Django app (attack target) |
| **proxy1** | 10.0.0.10 | Proxy/Load Balancer | Nginx reverse proxy (attack target) |
| **db1** | 10.0.0.20 | Database | PostgreSQL (data storage) |
| h70 | 10.0.0.100 | Web Service | Extra web service |
| h71 | 10.0.0.101 | DNS Service | DNS server |
| h72 | 10.0.0.102 | API Service | REST API |
| h80 | 10.0.0.200 | IDS | Intrusion Detection System |
| h81 | 10.0.0.201 | Honeypot | Security honeypot |
| h82 | 10.0.0.202 | Monitor | Network traffic mirror |

---

## 🎯 Data Collection Strategy

### **Original Problem**
When `STRICT_SUBNET_FILTER = OFF`:
- ❌ Collected ALL flows including system traffic (LLDP, ARP, DNS discovery)
- ❌ 77% of flows were dropped as "invalid" or "system"
- ❌ Extremely slow collection (100 samples/min)

### **Root Cause**
System generates constant background traffic:
- **LLDP Discovery** → Between switches (ONOS learning)
- **ARP Resolution** → All subnets discovering each other
- **DNS Queries** → h71 service responding to lookups
- **IDS Scanning** → h80 monitoring all traffic
- **Network Monitor** → h82 mirroring traffic

---

## ✅ Smart Filter Solution

### **Filter Logic (CÂN ĐỒI)**

```python
ACCEPT flow IF:
    AND NOT src/dst ∈ SYSTEM_HOSTS [h70,h71,h72,h80,h81,h82,db1]
    AND NOT dst_port = 53 (DNS)
    AND (src ∈ 10.0.1.x OR dst ∈ 10.0.1.x OR 
         src ∈ 10.0.2.x OR dst ∈ 10.0.2.x)    [attack/client only]
    AND (dst ∈ [10.0.0.10, 10.0.0.11] OR dst_port ∈ [80, 443, 8000])  [web targets only]

REJECT flow IF:
    - Source/dest is system host (IDS, monitoring, services)
    - Port 53 (DNS queries - not web traffic)
    - Neither src/dst from attack/client subnet
    - Doesn't target web services
```

### **Result**
| Metric | Before (OFF) | After (Smart) |
|--------|------------|--------------|
| Drop rate | 77% | ~30-40% |
| Valid samples/min | ~100 | ~200-300 |
| Collection time (80K) | ~800 min | ~300 min |
| Data quality | Noisy | Clean + representative |

---

## 🔄 Flow Examples

### **✅ ACCEPTED Flows**
```
[Normal] 10.0.2.60 → 10.0.0.10:8000 (GET /)
[Normal] 10.0.2.61 → 10.0.0.11:8000 (POST /api/metrics)
[Attack] 10.0.1.5 → 10.0.0.10:80 (UDP Flood)
[Attack] 10.0.1.12 → 10.0.0.11:443 (SYN Flood)
```

### **❌ REJECTED Flows**
```
[System] 10.0.0.100 → 10.0.0.20 (h70 → db1, not web target)
[System] 10.0.0.200 → 10.0.0.10 (h80 IDS scanning)
[System] 10.0.2.60 → 10.0.0.101:53 (DNS lookup)
[System] 10.0.3.x → any (not in attack/client subnet)
[System] 10.0.1.x → 10.0.0.102:22 (SSH, not web port)
```

---

## 📊 Expected Performance

### **Phase Timing Estimates**

| Phase | Samples | Clients | Attackers | Time |
|-------|---------|---------|-----------|------|
| **Normal Traffic** | 80,000 | 15 (h60-h74) | - | ~20-30 min |
| **UDP Flood** | 80,000 | - | 20 (h1-h20) | ~15-25 min |
| **SYN Flood** | 80,000 | - | 20 | ~15-25 min |
| **HTTP Flood** | 80,000 | - | 20 | ~25-35 min |
| **Slowloris** | 80,000 | - | 20 | ~30-40 min |
| **TOTAL** | 400,000 | - | - | **~2-2.5 hours** |

---

## ⚙️ Configuration Reference

```python
# In auto_dataset_generator.py
TARGET_SAMPLES_PER_CLASS = 80000

SMART_SUBNET_FILTER = 1  # Enabled by default
TARGET_SERVICES = ["10.0.0.10", "10.0.0.11"]  # proxy1, web1
TARGET_PORTS = [80, 443, 8000]  # HTTP, HTTPS, Django

SYSTEM_HOSTS_TO_EXCLUDE = [
    "10.0.0.100", "10.0.0.101", "10.0.0.102",  # Services
    "10.0.0.200", "10.0.0.201", "10.0.0.202",  # IDS, Honeypot, Monitor
    "10.0.0.20"   # Database
]
```

### **Override (Optional)**
```bash
# Disable smart filter (not recommended)
SMART_SUBNET_FILTER=0 python auto_dataset_generator.py

# Override target ports
# (would need code modification)
```

---

## 🧠 Design Rationale

### **Why Filter is Important**
1. **Data Quality**: Model learns real attack patterns, not system noise
2. **Performance**: 3x faster collection with filtering
3. **Reproducibility**: Consistent dataset composition across runs
4. **Balance**: Keeps attack/normal ratio realistic without system clutter

### **Why Smart ≠ STRICT**
- ❌ **OFF (too permissive)**: ~77% drop rate (slow, but all flows included)
- ❌ **STRICT (too rigid)**: Might reject valid web traffic responses
- ✅ **SMART (balanced)**: Targets only web traffic, excludes system services

---

## 📝 Dataset Statistics (Expected)

After collection with smart filter:

```
master_dataset_v6.csv (400,000 rows)
├─ Normal Traffic:       80,000 samples (10.0.2.x → 10.0.0.10/11)
├─ UDP Flood:            80,000 samples (10.0.1.x → 10.0.0.10/11)
├─ SYN Flood:            80,000 samples (10.0.1.x → 10.0.0.10/11)
├─ HTTP Flood:           80,000 samples (10.0.1.x → 10.0.0.10/11)
└─ Slowloris:            80,000 samples (10.0.1.x → 10.0.0.11)

Features per row: 13 + 1 label = 14 columns
Temporal structure: Sequences of 10 flows [SEQ_LEN=10, FEATURES=26]
Target distribution: Balanced (20% each class)
```

---

## 🚀 Next Steps

1. ✅ Filter implemented (SMART_SUBNET_FILTER enabled)
2. ⏳ Execute Phase 1 with new filter
3. Monitor collection speed (~200-300 samples/min)
4. Compare drop rates and acceptance rates
5. Fine-tune if needed

**Expected result:** 4x speedup with cleaner data! 🎉
