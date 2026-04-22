# Tên file: batPack.py
# Yêu cầu cài đặt: pip install nfstream psutil
from nfstream import NFStreamer
import time
import json
import threading
import psutil
import os

FIFO_PATH = "zeek_stream.json"

# ═══════════════════════════════════════════════════════════════════
# 🎯 CAPTURE INTERFACE OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════
# Prefer s6-eth1 (backbone) over s6-eth5 (Docker bridge with SNAT)
PREFERRED_INTERFACE = "s6-eth1"  # L3 backbone - preserves original IPs
FALLBACK_INTERFACES = ["s6-eth4", "h82-eth1", "s6-eth2"]  # Alternatives

# [BẢO VỆ TUYỆT ĐỐI 1]: Cấm cửa các cổng giao tiếp của SDN Controller
RESTRICTED_PORTS = [6653, 6633, 8181]

# [BẢO VỆ TUYỆT ĐỐI 2]: Khóa đa luồng chống dính chuỗi JSON (Interleaving)
pipe_lock = threading.Lock()

def _detect_interface():
    """Detect optimal capture interface: prefer s6-eth1 (backbone)"""
    try:
        nets = set(os.listdir("/sys/class/net"))
    except Exception:
        nets = set()
    
    # Try preferred interface first
    if PREFERRED_INTERFACE in nets:
        print(f"[INFO] Using optimal interface: {PREFERRED_INTERFACE} (L3 backbone)")
        return PREFERRED_INTERFACE
    
    # Try fallback interfaces
    for iface in FALLBACK_INTERFACES:
        if iface in nets:
            print(f"[WARN] {PREFERRED_INTERFACE} not found, using fallback: {iface}")
            return iface
    
    # Last resort - any s6-ethX interface
    for name in sorted(nets):
        if name.startswith("s6-eth"):
            print(f"[WARN] Using discovered interface: {name}")
            return name
    
    # Default
    print(f"[ERROR] No optimal interface found, defaulting to {PREFERRED_INTERFACE}")
    return PREFERRED_INTERFACE

def process_interface(iface_name=None):
    """Hàm chạy độc lập cho từng card mạng, do NFStream lõi C đảm nhiệm"""
    if iface_name is None:
        iface_name = _detect_interface()
    
    print(f"[+] Khởi động Radar NFStreamer trên cổng {iface_name}...")
    
    try:
        # TÍNH NĂNG ĐỈNH CAO: active_timeout=1
        # Ép NFStream tự động "chốt sổ" và nhả báo cáo mỗi 1 giây
        streamer = NFStreamer(
            source=iface_name, 
            active_timeout=1,   
            idle_timeout=2,
            statistical_analysis=True 
        )
        
        # --- BỘ ĐỆM XẢ LŨ (BATCHING) ---
        batch_json = []
        last_flush_time = time.time()
        
        for flow in streamer:
            # 1. BỘ LỌC RÁC
            if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                continue
            if flow.src_port in RESTRICTED_PORTS or flow.dst_port in RESTRICTED_PORTS:
                continue

            # 2. TÍNH TOÁN CÁC ĐẶC TRƯNG PHÁI SINH
            duration_sec = flow.bidirectional_duration_ms / 1000.0
            if duration_sec <= 0.0001: duration_sec = 0.001 

            pkt_rate = round(flow.bidirectional_packets / duration_sec, 4)
            byte_rate = round(flow.bidirectional_bytes / duration_sec, 4)
            duration_sec = round(duration_sec, 4)

            # 3. KỸ THUẬT FEATURE ENGINEERING TẦNG 7 (nDPI)
            app_name = str(flow.application_name).upper()
            l7_method_code = 0 
            if "HTTP" in app_name: l7_method_code = 1
            elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name: l7_method_code = 2
            elif "DNS" in app_name: l7_method_code = 3
            elif "OPENFLOW" in app_name: l7_method_code = 5
            
            if flow.protocol == 6: # TCP
                conn_state_code = 0 if flow.bidirectional_packets < 3 else 1
            elif flow.protocol == 17: # UDP
                conn_state_code = 2 
            else:
                conn_state_code = 0
                
            is_weird = 1 if (flow.src2dst_bytes > 0 and flow.dst2src_bytes == 0) else 0

            # ==========================================
            # 4. ÁNH XẠ DỮ LIỆU (FEATURE MAPPING) - 13 ĐẶC TRƯNG
            # Khớp 100% với mảng FEATURE_NAMES trong config.py
            # ==========================================
            # 0: Src_Port         (flow.src_port)
            # 1: Dst_Port         (flow.dst_port)
            # 2: Protocol         (flow.protocol)
            # 3: Duration_Sec     (duration_sec)
            # 4: Src_Bytes        (flow.src2dst_bytes)
            # 5: Dst_Bytes        (flow.dst2src_bytes)
            # 6: Src_Packets      (flow.src2dst_packets)
            # 7: Dst_Packets      (flow.dst2src_packets)
            # 8: Conn_State       (conn_state_code - Trạng thái TCP)
            # 9: L7_App_Protocol  (l7_method_code - Phân tích nDPI L7)
            # 10: Packet_Rate     (pkt_rate - Tốc độ gói tin)
            # 11: Byte_Rate       (byte_rate - Tốc độ Byte)
            # 12: Anomaly_Score   (is_weird - Dấu hiệu gói tin 1 chiều)
            
            features = [
                flow.src_port, flow.dst_port, flow.protocol, duration_sec,
                flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_packets, flow.dst2src_packets,
                conn_state_code, l7_method_code, pkt_rate, byte_rate, is_weird
            ]
            
            json_data = json.dumps({"ip": flow.src_ip, "features": features})
            batch_json.append(json_data + "\n")
            
            # 5. CƠ CHẾ XẢ LŨ AN TOÀN CHO MẠNG NƠ-RON
            current_time = time.time()
            if len(batch_json) >= 300 or (current_time - last_flush_time) > 1.0:
                if batch_json: 
                    # BẮT BUỘC DÙNG KHÓA: Đảm bảo 2 card s5 và s6 không tranh nhau ghi
                    with pipe_lock:
                        try:
                            with open(FIFO_PATH, 'a') as fifo:
                                fifo.writelines(batch_json) 
                        except (FileNotFoundError, BrokenPipeError):
                            # AI chưa bật hoặc vừa bị tắt (run_onos.py bị tắt)
                            # Bỏ qua lỗi âm thầm để Radar không bị sập theo AI
                            pass
                batch_json.clear()
                last_flush_time = current_time
                
    except Exception as e:
        print(f"[-] Lỗi nghiêm trọng trên cổng {iface_name}: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("🛰️  HỆ THỐNG RADAR NFSTREAM SẴN SÀNG (BẢN THỰC CHIẾN AI)")
    print("=" * 60)
    print("[*] Đang quét Vùng Lõi Datacenter (s5, s6)...")
    
    active_interfaces = []
    stats = psutil.net_if_stats()
    
    # BỘ LỌC CHUẨN XÁC: Chỉ áp tai vào các cổng Datacenter
    for iface_name, iface_stats in stats.items():
        if iface_stats.isup and (iface_name.startswith('s5-eth') or iface_name.startswith('s6-eth')):
            active_interfaces.append(iface_name)

    if not active_interfaces:
        print("[!] Không tìm thấy giao diện mạng s5 hoặc s6. Hãy chắc chắn Mininet đang chạy!")
        exit(1)

    print(f"[*] Tìm thấy {len(active_interfaces)} cổng phòng thủ: {active_interfaces}")
    print(f"[*] Phân bổ {len(active_interfaces)} lõi C-Engine độc lập...")

    # Phóng mỗi giao diện mạng vào 1 luồng NFStream riêng biệt
    threads = []
    for iface in active_interfaces:
        t = threading.Thread(target=process_interface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)

    # Giữ luồng chính chạy mãi mãi
    try:
        print("[*] Hệ thống Radar đang chạy ngầm. Hãy khởi động run_onos.py để hứng dữ liệu!")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Đã tắt hệ thống thu thập NFStream.")