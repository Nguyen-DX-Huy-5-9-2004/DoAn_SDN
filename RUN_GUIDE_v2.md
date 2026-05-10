# Hướng Dẫn Chạy Hệ Thống SDN IDS v2 (Unified Data Collection)

## 📊 Luồng Dữ Liệu Mới Sau Khi Gộp

```
┌──────────────────────────────────────────────────────────────────────┐
│  Terminal 2: batPack_v2.py (Đã gộp ONOS Metrics Collector)            │
│  ├──→ NFStreamer capture tại s6-eth1                                │
│  │    └──→ Ghi features vào FIFO (zeek_stream.json)  ──────────┐    │
│  │                                                              │    │
│  └──→ OnosMetricsCollector (thread nền)                         │    │
│       ├──→ Query ONOS REST API mỗi 2s                          │    │
│       ├──→ Đếm DROP/RATE_LIMIT flows                           │    │
│       └──→ Ghi unified_metrics.json ──────────┐                │    │
│                                                 │                │    │
└─────────────────────────────────────────────────┼────────────────┼────┘
                                                  │                │
┌─────────────────────────────────────────────────┼────────────────┘    │
│  Terminal 3: run_onos_v2.py (AI Detection)      │                     │
│  ├──→ Đọc FIFO (zeek_stream.json) ←─────────────┘                     │
│  ├──→ AI phân tích (Autoencoder + Classifier)                       │
│  └──→ Nếu phát hiện attack → Gọi ONOS API để DROP/RATE_LIMIT        │
└──────────────────────────────────────────────────────────────────────┘
                                                  │
┌─────────────────────────────────────────────────┘                     │
│  Dashboard (http://127.0.0.1:8050)                                    │
│  └──→ Đọc unified_metrics.json (từ batPack_v2)                      │
│       └──→ Hiển thị 3-Tier: Raw → Mitigated → Effective             │
└──────────────────────────────────────────────────────────────────────┘
```

## 🖥️ Cách Chạy (4 Terminal)

### **Terminal 1: Khởi động mạng**
```bash
cd /home/tgf/Documents/DoAn_SDN
./start.sh
```
**Chờ đến khi thấy:** `[HỆ THỐNG] TẤT CẢ DỊCH VỤ ĐÃ KHỞI ĐỘNG`

---

### **Terminal 2: Data Collection + Metrics (Đã gộp)**
```bash
cd /home/tgf/Documents/DoAn_SDN/ai
sudo /home/tgf/Documents/DoAn_SDN/sdn_env/bin/python batPack_v2.py --ids
```

**Chức năng:**
- ✅ Capture packets tại s6-eth1
- ✅ Trích xuất features (13 features) → FIFO
- ✅ **MỚI:** Query ONOS metrics mỗi 2s → unified_metrics.json

**Log mong đợi:**
```
[IFACE] Auto-detected optimal: s6-eth1
[ONOS-COLLECTOR] Started background thread
[STREAM] Starting on interface: s6-eth1
```

---

### **Terminal 3: AI Detection + Mitigation**
```bash
cd /home/tgf/Documents/DoAn_SDN/ai
sudo /home/tgf/Documents/DoAn_SDN/sdn_env/bin/python run_onos_v2.py
```

**Chức năng:**
- ✅ Đọc features từ FIFO (do batPack cung cấp)
- ✅ AI phát hiện attack
- ✅ Push flow rules lên ONOS (DROP/RATE_LIMIT)

**Log mong đợi:**
```
<<>> IDS Engine v2.1 Ready on cpu
<<>> Dual FIFO Mode: zeek_stream.json + zeek_stream_slowloris.json
```

**⚠️ QUAN TRỌNG:** Terminal 2 (batPack) và Terminal 3 (IDS) phải chạy **song song**:
- Nếu chỉ chạy batPack: FIFO bị đầy, features không được xử lý
- Nếu chỉ chạy IDS: Block đợi FIFO (chưa có data)

---

### **Terminal 4: Dashboard (nếu cần xem)**
```bash
cd /home/tgf/Documents/DoAn_SDN/dashboard
python3 server.py
```

**Truy cập:** http://127.0.0.1:8050

---

## 🧪 Test Attack (Trong containernet Terminal 1)

Sau khi cả 3 terminal trên đã chạy:

```bash
# UDP Flood attack từ h1, h2
py [net.get(f'h{i}').cmd('python3 attack/udp_flood.py 10.0.0.10 &') for i in range(1, 3)]
```

**Quan sát:**
- Terminal 2 (batPack): Vẫn chạy capture bình thường
- Terminal 2 (Collector log): `[ONOS-COLLECTOR] Written: X blocks, Y% protection`
- Terminal 3 (IDS): Hiển thị `IDS ALERT` và `XAI EXPLANATION`
- Dashboard: 3-Tier traffic hiển thị chính xác

---

## 🔍 Kiểm Tra Hoạt Động

### 1. Kiểm tra unified_metrics.json được tạo
```bash
tail -f /home/tgf/Documents/DoAn_SDN/monitor/runtime/unified_metrics.json | python3 -m json.tool
```

### 2. Kiểm tra dashboard đọc đúng file
Trong log dashboard (Terminal 4), mong đợi:
```
[DASHBOARD] Using unified metrics from batPack_v2
```

### 3. Kiểm tra ONOS flow rules
```bash
# Trong Terminal 1 (containernet)
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/flows | python3 -m json.tool | grep -A5 "DROP"
```

---

## ⚠️ Lưu Ý Quan Trọng

### Khác biệt so với trước:

| Trước khi gộp | Sau khi gộp |
|---------------|-------------|
| 5 process: start.sh + batPack + IDS + **collector** + dashboard | 4 process: start.sh + batPack (**đã có collector**) + IDS + dashboard |
| Collector query toàn mạng (6 switches, 35 hosts) | Collector query ONOS API (chỉ cần flow stats) |
| Dashboard hiển thị traffic tất cả hosts | Dashboard hiển thị 3-Tier: Raw → Mitigated → Effective |

### Các process cần chạy đồng thời:
```
✅ start.sh         (Terminal 1) - Infrastructure
✅ batPack_v2.py    (Terminal 2) - Capture + Metrics  
✅ run_onos_v2.py   (Terminal 3) - AI Detection
⬜ server.py        (Terminal 4) - Dashboard (optional)
```

### Không cần chạy nữa (đã gộp vào batPack):
```
❌ python monitor/onos_metrics_collector.py  (Đã gộp vào batPack_v2)
```

---

## 🚨 Troubleshooting

### Vấn đề 1: IDS không nhận data từ batPack
**Dấu hiệu:** Terminal 3 đứng yên, không có log
**Cách fix:** Kiểm tra Terminal 2 đã chạy chưa, FIFO đã tạo chưa:
```bash
ls -la /home/tgf/Documents/DoAn_SDN/ai/zeek_stream.json
```

### Vấn đề 2: Dashboard không có data
**Dấu hiệu:** Dashboard hiển thị "offline"
**Cách fix:** Kiểm tra file unified_metrics.json:
```bash
ls -la /home/tgf/Documents/DoAn_SDN/monitor/runtime/unified_metrics.json
cat /home/tgf/Documents/DoAn_SDN/monitor/runtime/unified_metrics.json
```

### Vấn đề 3: Collector không query được ONOS
**Dấu hiệu:** Log `[ONOS-COLLECTOR] API error`
**Cách fix:** Kiểm tra ONOS đã online:
```bash
curl -u onos:rocks http://127.0.0.1:8181/onos/v1/flows
```

---

## ✅ Checklist Trước Khi Chạy

- [ ] Terminal 1: `./start.sh` đã chạy xong, mạng đã sẵn sàng
- [ ] Terminal 2: `batPack_v2.py --ids` đã chạy, thấy log `[ONOS-COLLECTOR] Started`
- [ ] Terminal 3: `run_onos_v2.py` đã chạy, thấy log `IDS Engine v2.1 Ready`
- [ ] File `unified_metrics.json` đã được tạo
- [ ] Dashboard (nếu chạy) hiển thị "online"
- [ ] Sẵn sàng chạy attack để test
