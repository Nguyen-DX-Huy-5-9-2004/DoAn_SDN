# Tên file: batPack.py
# Yêu cầu cài đặt: pip install nfstream psutil
from nfstream import NFStreamer
import time
import json
import os
import threading
import psutil

FIFO_PATH = "zeek_stream.json"

# [BẢO VỆ TUYỆT ĐỐI 1]: Cấm cửa các cổng giao tiếp của SDN Controller
RESTRICTED_PORTS = [6653, 6633, 8181]

def process_interface(iface_name):
    """Hàm chạy độc lập cho từng card mạng, do NFStream lõi C đảm nhiệm"""
    print(f"[+] Khởi động NFStreamer trên cổng {iface_name}...")
    try:
        # TÍNH NĂNG ĐỈNH CAO: active_timeout=1
        streamer = NFStreamer(
            source=iface_name, 
            active_timeout=1,   
            idle_timeout=2,
            statistical_analysis=True 
        )
        
        # --- BÍ KÍP TỐI ƯU HIỆU NĂNG: Khởi tạo bộ đệm xả lũ ---
        batch_json = []
        last_flush_time = time.time()
        
        for flow in streamer:
            if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                continue

            if flow.src_port in RESTRICTED_PORTS or flow.dst_port in RESTRICTED_PORTS:
                continue

            duration_sec = flow.bidirectional_duration_ms / 1000.0
            if duration_sec <= 0.0001: duration_sec = 0.001 

            pkt_rate = round(flow.bidirectional_packets / duration_sec, 4)
            byte_rate = round(flow.bidirectional_bytes / duration_sec, 4)
            duration_sec = round(duration_sec, 4)

            app_name = str(flow.application_name).upper()
            l7_method_code = 0 
            if "HTTP" in app_name: l7_method_code = 1
            elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name: l7_method_code = 2
            elif "DNS" in app_name: l7_method_code = 3
            elif "OPENFLOW" in app_name: l7_method_code = 5
            
            if flow.protocol == 6:
                conn_state_code = 0 if flow.bidirectional_packets < 3 else 1
            elif flow.protocol == 17:
                conn_state_code = 2 
            else:
                conn_state_code = 0
                
            is_weird = 1 if (flow.src2dst_bytes > 0 and flow.dst2src_bytes == 0) else 0

            # ÁNH XẠ DỮ LIỆU (13 FEATURES)
            features = [
                flow.src_port, flow.dst_port, flow.protocol, duration_sec,
                flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_packets, flow.dst2src_packets,
                conn_state_code, l7_method_code, pkt_rate, byte_rate, is_weird
            ]
            
            json_data = json.dumps({"ip": flow.src_ip, "features": features})
            
            # 1. Đưa vào lô chờ
            batch_json.append(json_data + "\n")
            
            # 2. CHỐNG NGHẼN I/O: Chỉ xả ống RAM khi đủ 300 dòng HOẶC đã trôi qua 1 giây
            current_time = time.time()
            if len(batch_json) >= 300 or (current_time - last_flush_time) > 1.0:
                if batch_json: # Chỉ mở file nếu có dữ liệu
                    try:
                        with open(FIFO_PATH, 'a') as fifo:
                            fifo.writelines(batch_json) # Viết 1 cục 300 dòng một lúc
                    except (FileNotFoundError, BrokenPipeError):
                        pass
                batch_json.clear()
                last_flush_time = current_time
                
    except Exception as e:
        print(f"[-] Lỗi trên cổng {iface_name}: {e}")
    '''try:
        # TÍNH NĂNG ĐỈNH CAO: active_timeout=1
        # Ép NFStream tự động "chốt sổ" và nhả báo cáo mỗi 1 giây (Khớp với tốc độ của AI)
        streamer = NFStreamer(
            source=iface_name, 
            active_timeout=1,   
            idle_timeout=2,
            statistical_analysis=True # Bật tính toán thống kê (Rate, Duration...)
        )
        
        for flow in streamer:
            # Bỏ qua các luồng rác của localhost
            if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                continue

            # [BẢO VỆ TUYỆT ĐỐI 1]: Vứt bỏ gói tin của ONOS
            if flow.src_port in RESTRICTED_PORTS or flow.dst_port in RESTRICTED_PORTS:
                continue

            # Xử lý thời gian tránh chia cho 0
            duration_sec = flow.bidirectional_duration_ms / 1000.0
            if duration_sec <= 0.0001: duration_sec = 0.001 

            # [BẢO VỆ TUYỆT ĐỐI 3]: Làm tròn số thực, chống lỗi Infinity trong CSV
            pkt_rate = round(flow.bidirectional_packets / duration_sec, 4)
            byte_rate = round(flow.bidirectional_bytes / duration_sec, 4)
            duration_sec = round(duration_sec, 4)

            # ==========================================
            # ÁNH XẠ DỮ LIỆU (FEATURE MAPPING)
            # Ép thông số của NFStream vào đúng khuôn 20 cột của Zeek
            # ==========================================
            # features = [
            #     flow.src_port,          # 0: id.orig_p (NFStream lấy được Port)
            #     flow.dst_port,          # 1: id.resp_p (NFStream lấy được Port)
            #     flow.protocol,          # 2: proto (6: TCP, 17: UDP)
            #     duration_sec,           # 3: duration
            #     flow.src2dst_bytes,     # 4: orig_bytes
            #     flow.dst2src_bytes,     # 5: resp_bytes
            #     flow.src2dst_packets,   # 6: orig_pkts
            #     flow.dst2src_packets,   # 7: resp_pkts
            #     0,                      # 8: conn_state (L7 - Đệm 0)
            #     0,                      # 9: method (L7 - Đệm 0)
            #     0,                      # 10: request_body_len (L7 - Đệm 0)
            #     0,                      # 11: status_code (L7 - Đệm 0)
            #     pkt_rate,               # 12: pkt_rate (QUAN TRỌNG NHẤT)
            #     byte_rate,              # 13: byte_rate (QUAN TRỌNG NHẤT)
            #     0, 0, 0, 0, 0, 0        # 14-19: Padding các cột phụ
            # ]

            # ==========================================
            # KỸ THUẬT FEATURE ENGINEERING TẦNG 7 (nDPI -> Integer)
            # ==========================================
            app_name = str(flow.application_name).upper()
            
            # 1. Mã hóa Giao thức L7 (method / service)
            # Match với L7 của hệ thống: 1=HTTP, 2=TLS/HTTPS, 3=DNS, 5=OpenFlow, 0=Khác
            l7_method_code = 0 
            if "HTTP" in app_name: l7_method_code = 1
            elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name: l7_method_code = 2
            elif "DNS" in app_name: l7_method_code = 3
            elif "OPENFLOW" in app_name: l7_method_code = 5
            
            # 2. Ước lượng Trạng thái kết nối (conn_state)
            # 0: S0 (Kết nối chưa hoàn thành / SYN Flood)
            # 1: SF (Kết nối thành công / Lướt web bình thường / HTTP Flood / Slowloris)
            # 2: OTH (UDP / Không trạng thái)
            if flow.protocol == 6: # TCP
                conn_state_code = 0 if flow.bidirectional_packets < 3 else 1
            elif flow.protocol == 17: # UDP
                conn_state_code = 2 
            else:
                conn_state_code = 0
                
            # 3. Ước lượng độ dị thường (is_weird)
            # Tấn công Spoofing/Flood thường chỉ gửi 1 chiều, chiều về (dst2src) = 0
            is_weird = 1 if (flow.src2dst_bytes > 0 and flow.dst2src_bytes == 0) else 0

            # ==========================================
            # ÁNH XẠ DỮ LIỆU (20 FEATURES)
            # ==========================================
            features = [
                flow.src_port,          # 0: id.orig_p
                flow.dst_port,          # 1: id.resp_p
                flow.protocol,          # 2: proto 
                duration_sec,           # 3: duration
                flow.src2dst_bytes,     # 4: orig_bytes
                flow.dst2src_bytes,     # 5: resp_bytes
                flow.src2dst_packets,   # 6: orig_pkts
                flow.dst2src_packets,   # 7: resp_pkts
                conn_state_code,        # 8: conn_state (AI sẽ học được SYN Flood ở đây vì nó = 0)
                l7_method_code,         # 9: method (AI sẽ phân biệt được HTTP Flood (1,2) và UDP (0))
                pkt_rate,               # 10: pkt_rate
                byte_rate,              # 11: byte_rate
                is_weird,               # 12: is_weird (Hữu ích cho các đòn Flood rác)
            ]
            
            json_data = json.dumps({"ip": flow.src_ip, "features": features})
            
            # Đẩy vào ống RAM cho AI
            try:
                with open(FIFO_PATH, 'a') as fifo:
                    fifo.write(json_data + "\n")
                    fifo.flush()
            except (FileNotFoundError, BrokenPipeError):
                pass
                
    except Exception as e:
        print(f"[-] Lỗi trên cổng {iface_name}: {e}")'''

if __name__ == "__main__":
    print("[*] Đang quét Vùng Lõi Datacenter (s5, s6)...")
    active_interfaces = []
    stats = psutil.net_if_stats()
    
    # BỘ LỌC CHUẨN XÁC: Chỉ áp tai vào các cổng Datacenter (Tránh nhân bản gói tin)
    for iface_name, iface_stats in stats.items():
        if iface_stats.isup and (iface_name.startswith('s5-eth') or iface_name.startswith('s6-eth')):
            active_interfaces.append(iface_name)

    print(f"[*] Tìm thấy {len(active_interfaces)} cổng phòng thủ: {active_interfaces}")
    print(f"[*] Khởi động Bộ máy NFStream đa luồng (C-Engine)...")

    # Phóng mỗi giao diện mạng vào 1 luồng NFStream riêng biệt
    threads = []
    for iface in active_interfaces:
        t = threading.Thread(target=process_interface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)

    # Giữ luồng chính chạy mãi mãi
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Đã tắt hệ thống thu thập NFStream.")