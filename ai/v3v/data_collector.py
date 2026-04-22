# Tên file: data_collector.py
'''data_collector.py -> LỖI THỜI (HÃY XÓA/BỎ QUA)

Đánh giá: Đây là file dùng để gán nhãn thủ công (bấm phím 0-5) từ phiên bản v2 cũ. Ở bản v4, chúng ta đã có script auto_dataset_generator.py tự động hóa toàn bộ việc này rồi.

Kết luận: Bạn không cần dùng đến file này nữa. Việc giữ lại có thể gây nhầm lẫn đường dẫn file CSV sau này.'''
import json
import os
import time
import threading
import csv
import random
import signal
import sys

FIFO_PATH = "zeek_stream.json"
OUTPUT_CSV = "master_dataset_v2.csv"

# Cấu trúc 13 Đặc trưng + 1 Nhãn
HEADERS = [
    "id.orig_p","id.resp_p","proto","duration","orig_bytes","resp_bytes",
    "orig_pkts","resp_pkts","conn_state","method",
    "pkt_rate","byte_rate","is_weird","target_label"
]
LABELS = {
    "0": "Normal (Bình thường)",
    "1": "UDP Flood",
    "2": "SYN Flood",
    "3": "HTTP Flood",
    "4": "Slowloris",
    "5": "TẠM DỪNG GHI (PAUSE)"
}

current_label = "5" 
samples_collected = {k: 0 for k in LABELS.keys()}
ignore_until = 0.0 # Biến dùng để bỏ qua rác RAM thay cho lệnh fifo.read() gây treo

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def user_input_thread():
    global current_label, ignore_until
    while True:
        clear_screen()
        print("="*65)
        print(" 🎯 BẢNG ĐIỀU KHIỂN GHI NHÃN DỮ LIỆU (CHỐNG CHẠY NGẦM) ")
        print("="*65)
        for k, v in LABELS.items():
            print(f"  [{k}] {v:<22} | Đã thu: {samples_collected[k]:>6} mẫu")
        print("="*65)
        
        status_color = "🔴 ĐANG TẠM DỪNG" if current_label == "5" else f"🟢 ĐANG GHI: {LABELS[current_label].upper()}"
        print(f" [*] TRẠNG THÁI: >>> {status_color} <<<")
        print("-" * 65)
        
        new_label = input(f"Nhập số (0-5) để đổi nhãn, hoặc Enter để làm mới: ")
        if new_label in LABELS:
            if current_label != "5" and new_label != "5":
                print("\n⚠️ Hãy chuyển về phím [5] (PAUSE) trước để làm sạch ống RAM!")
                time.sleep(2)
                continue
                
            current_label = new_label
            if current_label != "5":
                # CHỐNG RÒ RỈ NHÃN: Bỏ qua mọi dữ liệu trong 1.5 giây đầu tiên
                ignore_until = time.time() + 1.5 

buffer_writes = []

def save_and_exit(signum, frame):
    """CỨU HỘ DỮ LIỆU: Bắt mọi tín hiệu tắt máy để lưu nốt RAM xuống SSD"""
    global buffer_writes
    if buffer_writes:
        with open(OUTPUT_CSV, mode='a', newline='') as f:
            csv.writer(f).writerows(buffer_writes)
    clear_screen()
    print(f"\n[✅] CỨU DỮ LIỆU THÀNH CÔNG! Đã lưu an toàn vào {OUTPUT_CSV}")
    print(f"[📊] Thống kê: {samples_collected}")
    sys.exit(0)

# Gắn hệ thống cứu hộ vào tín hiệu Ctrl+C (SIGINT) và Tắt ngầm (SIGTERM)
signal.signal(signal.SIGINT, save_and_exit)
signal.signal(signal.SIGTERM, save_and_exit)

if __name__ == "__main__":
    file_exists = os.path.isfile(OUTPUT_CSV)
    with open(OUTPUT_CSV, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists: writer.writerow(HEADERS)
            
    if not os.path.exists(FIFO_PATH): os.mkfifo(FIFO_PATH)

    threading.Thread(target=user_input_thread, daemon=True).start()

    last_flush = time.time()
    while True:
        try:
            with open(FIFO_PATH, 'r') as fifo:
                for line in fifo:
                    if not line.strip() or current_label == "5": continue
                    
                    # Bỏ qua dữ liệu rác trong 1.5s đầu tiên
                    if time.time() < ignore_until: continue
                    
                    # Smart Downsampling (Cân bằng Data)
                    if current_label in ["1", "2", "3"]:
                        if random.random() > 0.05: continue 
                            
                    try:
                        data = json.loads(line)
                        features = data.get("features", [])
                        if len(features) == 13:
                            features.append(int(current_label))
                            buffer_writes.append(features)
                            samples_collected[current_label] += 1
                            
                            # Ghi theo lô để chống lag máy
                            if len(buffer_writes) >= 150 or (time.time() - last_flush) > 2:
                                with open(OUTPUT_CSV, mode='a', newline='') as f:
                                    csv.writer(f).writerows(buffer_writes)
                                buffer_writes = []
                                last_flush = time.time()
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            time.sleep(1)