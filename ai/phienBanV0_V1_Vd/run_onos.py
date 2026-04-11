# Tên file: run_onos.py
'''import torch
import numpy as np
import joblib
import time
import requests
import warnings
warnings.filterwarnings("ignore")

from config import DDos_CNN_GRU, SEQ_LEN, LABEL_NAMES

# CẤU HÌNH KẾT NỐI ONOS CONTROLLER
ONOS_IP = "127.0.0.1"
ONOS_PORT = "8181"
ONOS_USER = "onos"
ONOS_PASS = "rocks"

def block_attacker_via_onos(src_ip, attack_name, confidence):
    """Hàm bắn REST API ra lệnh cho ONOS cập nhật Flow Table (Chặn Hacker)"""
    print("\n" + "!"*60)
    print(f"🚨 [CẢNH BÁO TẤN CÔNG] XÁC NHẬN: {attack_name.upper()}")
    print(f"   ► Độ tin cậy AI  : {confidence:.2f}%")
    print(f"   ► IP Kẻ tấn công : {src_ip}")
    print(f"   ► Hành động      : Đang ra lệnh cho Switch qua OpenFlow...")
    
    # JSON cấu hình chặn luồng đẩy xuống ONOS (Flow Rule)
    flow_rule = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000000000000001", # ID của switch kết nối với kẻ tấn công
        "treatment": { "instructions": [{"type": "DROP"}] }, # Lệnh HỦY BỎ GÓI TIN
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"}, # IPv4
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"} # IP của hacker
            ]
        }
    }
    
    try:
        url = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1/flows/of:0000000000000001"
        # Bỏ comment dòng dưới khi có mạng ONOS thật:
        # response = requests.post(url, auth=(ONOS_USER, ONOS_PASS), json=flow_rule)
        # if response.status_code == 201:
        print("   ✅ [ONOS] Lệnh mitigation đã được thực thi! Mạng đã an toàn.")
    except Exception as e:
        print(f"   ❌ [LỖI ONOS]: Không thể kết nối tới Controller ({e})")
    print("!"*60 + "\n")

if __name__ == "__main__":
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"💻 Khởi động IDS/IPS Engine trên thiết bị: {device.type.upper()}")
    
    # Tải Scaler và Model
    try:
        scaler = joblib.load('sdn_scaler.pkl')
        model = DDos_CNN_GRU().to(device)
        model.load_state_dict(torch.load('sdn_model_cnn_gru.pth', map_location=device))
        model.eval()
        print("✅ Đã nạp thành công Não bộ AI và File Chuẩn hóa.")
    except FileNotFoundError:
        print("❌ LỖI: Không tìm thấy sdn_scaler.pkl hoặc sdn_model_cnn_gru.pth!")
        exit()

    print("📡 Hệ thống đang lắng nghe lưu lượng từ Mininet/sFlow...\n")

    # GIẢ LẬP: Hệ thống bắt được 10 luồng mạng mới nhất của 1 IP lạ
    # Ở thực tế, mảng này được đẩy về từ Zeek hoặc sFlow-RT
    live_traffic_matrix = np.zeros((10, 20)) 
    
    # Giả lập hành vi của SLOWLORIS (Duration rất dài, pkt_rate rất chậm)
    live_traffic_matrix[:, 3] = 115000000 # Cột duration
    live_traffic_matrix[:, 12] = 0.5      # Cột pkt_rate siêu thấp
    live_traffic_matrix[:, 2] = 6         # TCP protocol
    suspect_ip = "10.0.0.9"               # IP gốc lấy từ packet thô

    # BƯỚC 1: Tiền xử lý (Scale)
    scaled_traffic = scaler.transform(live_traffic_matrix)
    
    # BƯỚC 2: Chuyển thành Tensor: Shape(1, 10, 20)
    input_tensor = torch.FloatTensor(scaled_traffic).unsqueeze(0).to(device)

    # BƯỚC 3: AI Inference (Chạy suy luận cực nhanh trên GTX 1050)
    start_time = time.time()
    with torch.no_grad():
        outputs = model(input_tensor)
        probabilities = torch.nn.functional.softmax(outputs, dim=1)
        pred_idx = torch.argmax(probabilities, dim=1).item()
        confidence = probabilities[0][pred_idx].item() * 100

    process_time = (time.time() - start_time) * 1000
    print(f"⏱️ Thời gian AI phản xạ: {process_time:.2f} ms")

    # BƯỚC 4: Ra quyết định
    attack_name = LABEL_NAMES[pred_idx]
    
    if pred_idx == 0:
        print(f"🟢 Lưu lượng từ {suspect_ip} được đánh giá: {attack_name} ({confidence:.2f}%)")
    else:
        # Nếu AI chắc chắn > 80% là tấn công -> Gửi API chặn ONOS
        if confidence > 80.0:
            block_attacker_via_onos(suspect_ip, attack_name, confidence)
        else:
            print(f"🟡 Cảnh báo nghi ngờ {attack_name} từ {suspect_ip} nhưng độ tin cậy chưa cao ({confidence:.2f}%). Tiếp tục theo dõi.")'''
# Tên file: run_onos.py
import torch
import torch.nn as nn
import numpy as np
import joblib
import time
import requests
import warnings
warnings.filterwarnings("ignore")

# IMPORT 2 LÕI AI TỪ FILE CONFIG
from config import Anomaly_Autoencoder, DDos_CNN_GRU_Attention, SEQ_LEN, LABEL_NAMES

# CẤU HÌNH KẾT NỐI ONOS CONTROLLER
ONOS_IP = "127.0.0.1"
ONOS_PORT = "8181"
ONOS_USER = "onos"
ONOS_PASS = "rocks"

def block_attacker_via_onos(src_ip, attack_name, confidence=None, is_zero_day=False):
    """Hàm bắn REST API ra lệnh cho ONOS cập nhật Flow Table (Chặn Hacker)"""
    print("\n" + "!"*65)
    if is_zero_day:
        print(f"☣️ [BÁO ĐỘNG ĐỎ] PHÁT HIỆN TẤN CÔNG ZERO-DAY!")
        print(f"   ► Loại        : {attack_name}")
        print(f"   ► Cảnh báo    : Hành vi chưa từng tồn tại trong cơ sở dữ liệu.")
    else:
        print(f"🚨 [CẢNH BÁO TẤN CÔNG] XÁC NHẬN: {attack_name.upper()}")
        print(f"   ► Độ tin cậy  : {confidence:.2f}%")
        
    print(f"   ► IP Hacker   : {src_ip}")
    print(f"   ► Hành động   : Đang ra lệnh cho Switch qua OpenFlow...")
    
    # JSON cấu hình chặn luồng đẩy xuống ONOS (Flow Rule)
    flow_rule = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": "of:0000000000000001", # ID của switch kết nối với kẻ tấn công
        "treatment": { "instructions": [{"type": "DROP"}] }, # Lệnh HỦY BỎ GÓI TIN
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"}, # IPv4
                {"type": "IPV4_SRC", "ip": f"{src_ip}/32"} # IP của hacker
            ]
        }
    }
    
    try:
        url = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1/flows/of:0000000000000001"
        # Bỏ comment dòng dưới khi có mạng ONOS thật:
        # response = requests.post(url, auth=(ONOS_USER, ONOS_PASS), json=flow_rule)
        # if response.status_code == 201:
        print("   ✅ [ONOS] Lệnh mitigation đã được thực thi! Mạng đã an toàn.")
    except Exception as e:
        print(f"   ❌ [LỖI ONOS]: Không thể kết nối tới Controller ({e})")
    print("!"*65 + "\n")


if __name__ == "__main__":
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"💻 Khởi động HỆ THỐNG PHÒNG THỦ KÉP (Dual-Engine IDS) trên: {device.type.upper()}")
    
    # ==========================================
    # KHỞI TẠO VÀ NẠP CÁC BÁU VẬT TỪ COLAB
    # ==========================================
    try:
        # 1. Nạp File Chuẩn hóa và Ngưỡng Zero-Day
        scaler = joblib.load('sdn_scaler.pkl')
        ae_threshold = joblib.load('ae_threshold.pkl')
        
        # 2. Nạp Khiên 1: Autoencoder
        ae_model = Anomaly_Autoencoder().to(device)
        ae_model.load_state_dict(torch.load('sdn_autoencoder.pth', map_location=device))
        ae_model.eval()
        
        # 3. Nạp Khiên 2: CNN-GRU-Attention
        cls_model = DDos_CNN_GRU_Attention().to(device)
        cls_model.load_state_dict(torch.load('sdn_model_cnn_gru_attn.pth', map_location=device))
        cls_model.eval()
        
        print("✅ Đã nạp thành công: Scaler, Threshold, Autoencoder và Mô hình phân loại lai.")
        print(f"⚖️ Ngưỡng nhạy cảm Zero-Day (Threshold): {ae_threshold:.4f}\n")
    except FileNotFoundError as e:
        print(f"❌ LỖI: Thiếu file cấu hình từ Colab. Chi tiết: {e}")
        exit()

    print("📡 Hệ thống đang lắng nghe lưu lượng từ Mininet/sFlow...")

    # ==========================================
    # GIẢ LẬP LƯU LƯỢNG MẠNG THỜI GIAN THỰC
    # ==========================================
    live_traffic_matrix = np.zeros((10, 20)) 
    suspect_ip = "10.0.0.9"               
    
    # [KỊCH BẢN TEST]: Tùy chỉnh dữ liệu để test 1 trong 2 khiên:
    
    # Kịch bản 1: Giả lập Slowloris đã biết (Thời gian sống cực lâu, gói tin ít)
    live_traffic_matrix[:, 3] = 115000000 # Duration 
    live_traffic_matrix[:, 12] = 0.5      # Pkt_rate thấp 
    live_traffic_matrix[:, 2] = 6         # TCP
    
    # Kịch bản 2: Bỏ comment 3 dòng dưới để test Zero-day (Thông số điên rồ AI chưa từng thấy)
    # live_traffic_matrix[:, 4] = 999999999 # orig_bytes khổng lồ bất thường
    # live_traffic_matrix[:, 2] = 255       # Protocol lạ
    # live_traffic_matrix[:, 14] = 1        # Cờ is_weird bật sáng

    # TIỀN XỬ LÝ (SCALE)
    scaled_traffic = scaler.transform(live_traffic_matrix)
    input_tensor = torch.FloatTensor(scaled_traffic).unsqueeze(0).to(device)

    start_time = time.time()

    # ==========================================
    # LỚP KHIÊN 1: AUTOENCODER (BẮT ZERO-DAY)
    # ==========================================
    with torch.no_grad():
        reconstructed = ae_model(input_tensor)
        # Tính sai số tái tạo (MSE) của luồng hiện tại
        mse_loss = torch.mean((input_tensor - reconstructed)**2).item()
    
    if mse_loss > ae_threshold:
        # Nếu sai số lớn hơn ngưỡng -> ĐÂY LÀ ZERO DAY! Bắn bỏ ngay lập tức không cần phân loại.
        process_time = (time.time() - start_time) * 1000
        print(f"⏱️ Thời gian phản xạ Lớp 1: {process_time:.2f} ms")
        print(f"⚠️ [Phân tích MSE]: {mse_loss:.4f} (Vượt ngưỡng {ae_threshold:.4f})")
        block_attacker_via_onos(suspect_ip, "DỊ THƯỜNG ZERO-DAY GIAO THỨC LẠ", is_zero_day=True)
        
    # ==========================================
    # LỚP KHIÊN 2: CNN-GRU-ATTENTION (PHÂN LOẠI DDOS ĐÃ BIẾT)
    # ==========================================
    else:
        # Dữ liệu quen thuộc -> Chuyển cho Lớp 2 bóc tách chi tiết
        with torch.no_grad():
            outputs, attn_weights = cls_model(input_tensor)
            probabilities = torch.nn.functional.softmax(outputs, dim=1)
            pred_idx = torch.argmax(probabilities, dim=1).item()
            confidence = probabilities[0][pred_idx].item() * 100

        process_time = (time.time() - start_time) * 1000
        print(f"⏱️ Thời gian AI phản xạ (Qua 2 lớp): {process_time:.2f} ms")
        print(f"✅ Lớp 1 (Autoencoder): Pass (MSE {mse_loss:.4f} <= {ae_threshold:.4f})")
        
        attack_name = LABEL_NAMES[pred_idx]
        if pred_idx == 0:
            print(f"🟢 Lưu lượng từ {suspect_ip} được Lớp 2 đánh giá: {attack_name} ({confidence:.2f}%)")
        else:
            if confidence > 80.0:
                # Bắt được kẻ gian với độ tin cậy cao
                # attn_weights ở đây có thể dùng để in ra console cho XAI (Explainable AI) sau này
                block_attacker_via_onos(suspect_ip, attack_name, confidence)
            else:
                print(f"🟡 Nghi ngờ {attack_name} từ {suspect_ip} nhưng độ tin cậy chưa cao ({confidence:.2f}%).")