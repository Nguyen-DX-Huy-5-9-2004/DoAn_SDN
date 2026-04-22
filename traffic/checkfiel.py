import requests
from requests.auth import HTTPBasicAuth
import time
import csv
import os

# ================= CẤU HÌNH =================
ONOS_IP = '127.0.0.1'
ONOS_PORT = '8181'
ONOS_USER = 'onos'
ONOS_PASS = 'rocks'
# Đường dẫn tới file log của Zeek (nơi bạn chạy lệnh zeek -i)
ZEEK_HTTP_LOG = "http.log" 

INTERVAL = 3  # Chu kỳ 3 giây cho GRU
CURRENT_LABEL = 0 # 0: Benign, 1: DDoS
CSV_FILENAME = "hybrid_l4_l7_dataset.csv"
# ============================================

def get_onos_l4_stats():
    """Lấy dữ liệu tầng 4 từ ONOS API"""
    url = f'http://{ONOS_IP}:{ONOS_PORT}/onos/v1/flows'
    try:
        res = requests.get(url, auth=HTTPBasicAuth(ONOS_USER, ONOS_PASS), timeout=2)
        if res.status_code == 200:
            return res.json().get('flows', [])
    except:
        return []
    return []

def get_zeek_l7_stats():
    """Đọc file http.log của Zeek để lấy đặc trưng tầng 7"""
    l7_data = {}
    if not os.path.exists(ZEEK_HTTP_LOG):
        return l7_data

    try:
        with open(ZEEK_HTTP_LOG, 'r') as f:
            lines = f.readlines()
            # Zeek logs thường có header ở các dòng đầu, ta lấy các dòng dữ liệu mới
            for line in lines:
                if line.startswith("#"): continue
                fields = line.strip().split('\t')
                # Cấu trúc mặc định của Zeek http.log (có thể thay đổi tùy phiên bản)
                # Thường: [1] id.orig_h, [3] id.resp_h, [7] method, [8] uri, [10] request_body_len
                if len(fields) > 10:
                    src_ip = fields[2]
                    method = fields[7]
                    uri = fields[8]
                    body_len = int(fields[10]) if fields[10] != '-' else 0
                    
                    key = src_ip
                    if key not in l7_data:
                        l7_data[key] = {'get_pc': 0, 'post_pc': 0, 'uri_set': set(), 'avg_body': []}
                    
                    if method == "GET": l7_data[key]['get_pc'] += 1
                    elif method == "POST": l7_data[key]['post_pc'] += 1
                    l7_data[key]['uri_set'].add(uri)
                    l7_data[key]['avg_body'].append(body_len)
        
        # Sau khi đọc xong, ta có thể xóa hoặc làm trống file log để chu kỳ sau không đọc lại dữ liệu cũ
        #open(ZEEK_HTTP_LOG, 'w').close() 
    except Exception as e:
        print(f"Lỗi đọc Zeek log: {e}")
    
    return l7_data

def main():
    headers = [
        'src_ip', 'pkt_count', 'byte_count', 'pkt_rate', 'byte_rate', # L4 (ONOS)
        'http_get_count', 'http_post_count', 'unique_uri_count', 'avg_body_len', # L7 (Zeek)
        'label'
    ]
    
    with open(CSV_FILENAME, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)

    prev_stats = {}

    print(f"[*] Bắt đầu thu thập Hybrid Dataset (Label: {CURRENT_LABEL})...")
    
    try:
        while True:
            flows = get_onos_l4_stats()
            l7_stats = get_zeek_l7_stats()
            
            with open(CSV_FILENAME, 'a', newline='') as f:
                writer = csv.writer(f)
                
                for flow in flows:
                    if flow.get('appId') == 'org.onosproject.core': continue
                    
                    # Trích xuất IP nguồn từ selector
                    src_ip = "0.0.0.0"
                    for c in flow.get('selector', {}).get('criteria', []):
                        if c.get('type') == 'IPV4_SRC': src_ip = c.get('ip').split('/')[0]

                    flow_id = flow.get('id')
                    pkts = int(flow.get('packets', 0))
                    bytes_cnt = int(flow.get('bytes', 0))
                    
                    # Tính Rate (L4)
                    pkt_rate = 0
                    if flow_id in prev_stats:
                        pkt_rate = (pkts - prev_stats[flow_id]) / INTERVAL
                    prev_stats[flow_id] = pkts

                    # Lấy dữ liệu L7 tương ứng với IP nguồn này
                    l7 = l7_stats.get(src_ip, {'get_pc': 0, 'post_pc': 0, 'uri_set': set(), 'avg_body': []})
                    avg_body = sum(l7['avg_body'])/len(l7['avg_body']) if l7['avg_body'] else 0
                    
                    row = [
                        src_ip, pkts, bytes_cnt, pkt_rate, (bytes_cnt/INTERVAL),
                        l7['get_pc'], l7['post_pc'], len(l7['uri_set']), avg_body,
                        CURRENT_LABEL
                    ]
                    writer.writerow(row)
            
            print(f"[*] Đã cập nhật chu kỳ mới. Đang đợi {INTERVAL}s...")
            time.sleep(INTERVAL)
            
    except KeyboardInterrupt:
        print("Dừng thu thập.")

if __name__ == "__main__":
    main()