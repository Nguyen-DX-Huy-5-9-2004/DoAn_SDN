# Tên file: batPack.py
# Yêu cầu cài đặt: pip install scapy psutil
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import time
import json
import os
import threading
import psutil

FIFO_PATH = "zeek_stream.json"

INTERVAL = 1.0 
flow_stats = {}
stats_lock = threading.Lock()
packet_count_debug = 0  # Đếm số gói bắt được để in ra màn hình

def process_packet(packet):
    global packet_count_debug
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Bỏ qua các luồng của chính máy chủ/hệ thống
        if src_ip.startswith("127.") or src_ip == "0.0.0.0":
            return
            
        proto = packet[IP].proto
        pkt_length = len(packet)

        with stats_lock:
            if src_ip not in flow_stats:
                flow_stats[src_ip] = {
                    'proto': proto,
                    'start_time': time.time(),
                    'orig_pkts': 0,
                    'orig_bytes': 0
                }
            
            # Cộng dồn số liệu
            flow_stats[src_ip]['orig_pkts'] += 1
            flow_stats[src_ip]['orig_bytes'] += pkt_length
            
            # --- IN RA DEBUG ĐỂ CHỨNG MINH SCAPY ĐANG BẮT ĐƯỢC MẠNG MININET ---
            packet_count_debug += 1
            if packet_count_debug % 10000 == 0:
                print(f"[SCAPY DEBUG] Mẻ lưới vừa rồi bắt được {packet_count_debug} gói tin từ Mininet...")

def feature_builder_worker():
    """Luồng chạy ngầm: Cứ 1 giây lại tính toán tốc độ và đẩy JSON vào ống RAM"""
    while True:
        time.sleep(INTERVAL)
        current_time = time.time()
        
        with stats_lock:
            ips_to_process = list(flow_stats.keys())
            
            for src_ip in ips_to_process:
                stats = flow_stats[src_ip]
                
                # Nếu 1 giây qua IP này không gửi gì thì bỏ qua
                if stats['orig_pkts'] == 0:
                    continue 
                    
                duration = current_time - stats['start_time']
                pkt_rate = stats['orig_pkts'] / INTERVAL
                byte_rate = stats['orig_bytes'] / INTERVAL
                
                features = [
                    0,                   # 0: id.orig_p (Bỏ qua, gán 0)
                    0,                   # 1: id.resp_p (Bỏ qua, gán 0)
                    stats['proto'],      # 2: proto (6 là TCP, 17 là UDP)
                    duration,            # 3: duration
                    stats['orig_bytes'], # 4: orig_bytes
                    0,                   # 5: resp_bytes
                    stats['orig_pkts'],  # 6: orig_pkts
                    0,                   # 7: resp_pkts
                    0,                   # 8: conn_state
                    0,                   # 9: method
                    0,                   # 10: request_body_len
                    0,                   # 11: status_code
                    pkt_rate,            # 12: pkt_rate (CỘT QUAN TRỌNG NHẤT)
                    byte_rate,           # 13: byte_rate
                    0, 0, 0, 0, 0, 0     # 14-19: Padding các cột phụ
                ]
                
                json_data = json.dumps({"ip": src_ip, "features": features})
                
                try:
                    with open(FIFO_PATH, 'a') as fifo:
                        fifo.write(json_data + "\n")
                        fifo.flush()  # ÉP ĐẨY DỮ LIỆU NGAY LẬP TỨC KHỎI RAM CHỜ
                except FileNotFoundError:
                    pass
                except BrokenPipeError:
                    pass
                
                # Reset đếm cho chu kỳ giây tiếp theo
                stats['orig_pkts'] = 0
                stats['orig_bytes'] = 0

print(f"[*] Đang quét danh sách các card mạng khả dụng...")

# Lấy danh sách các card mạng đang có trạng thái UP
active_interfaces = []
stats = psutil.net_if_stats()
for iface_name, iface_stats in stats.items():
    # Chỉ lấy card ĐANG BẬT và có TÊN LÀ CỔNG SWITCH (bắt đầu bằng s và có chữ eth)
    # Ví dụ: s1-eth1, s4-eth2...
    if iface_stats.isup and iface_name.startswith('s') and '-eth' in iface_name:
        active_interfaces.append(iface_name)

print(f"[*] Đã tìm thấy {len(active_interfaces)} cổng SDN Mininet: {active_interfaces}")

print(f"[*] Bắt đầu nghe lén lưu lượng...")
print(f"[*] Dữ liệu sau khi trích xuất sẽ được bơm liên tục vào {FIFO_PATH} cho AI...")

threading.Thread(target=feature_builder_worker, daemon=True).start()

# Lắng nghe chỉ trên các card mạng đang UP
try:
    sniff(iface=active_interfaces, prn=process_packet, store=False)
except Exception as e:
    print(f"Lỗi khi khởi động sniffer: {e}")