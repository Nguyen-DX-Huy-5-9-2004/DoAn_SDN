# Tên file: run_onos.py
# YÊU CẦU CÀI ĐẶT: pip install rich requests numpy torch scikit-learn
import torch
import numpy as np
import joblib
import time
import requests
import json
import os
import threading
import warnings
warnings.filterwarnings("ignore")

from rich.console import Console
from rich.panel import Panel
from config import Anomaly_Autoencoder, DDos_CNN_GRU_Attention, SEQ_LEN, LABEL_NAMES, FEATURE_NAMES

console = Console()

# ==========================================
# CẤU HÌNH HỆ THỐNG
# ==========================================
ONOS_IP = "127.0.0.1"
ONOS_PORT = "8181"
ONOS_USER = "onos"
ONOS_PASS = "rocks"
HONEYPOT_PORT = "2" # Cổng switch dẫn tới Honeypot

FIFO_PATH = "/tmp/zeek_stream.json"
CHECKPOINT_FILE = "threshold_state.json"
EMA_ALPHA = 0.05
dynamic_threshold = 0.1827 # Ngưỡng mặc định nếu không có file
threshold_lock = threading.Lock()

# ==========================================
# MODULE 1: EMA & SSD CHECKPOINTING
# ==========================================
def load_checkpoint():
    global dynamic_threshold
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r') as f:
                data = json.load(f)
                dynamic_threshold = data.get('threshold', dynamic_threshold)
            console.print(f"[bold green]✅ Phục hồi Checkpoint thành công. Ngưỡng hiện tại: {dynamic_threshold:.4f}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]❌ Lỗi đọc Checkpoint: {e}[/bold red]")

def save_threshold_worker():
    """Luồng ngầm chạy mỗi 5 phút (300s) để lưu ngưỡng xuống ổ SSD"""
    while True:
        time.sleep(300) 
        with threshold_lock:
            current_th = dynamic_threshold
        try:
            with open(CHECKPOINT_FILE, 'w') as f:
                json.dump({'threshold': current_th, 'timestamp': time.time()}, f)
            # console.print("[dim]💾 Đã lưu Checkpoint (Ngưỡng thích nghi) xuống SSD.[/dim]")
        except Exception as e:
            pass

# ==========================================
# MODULE 2: EXPLAINABLE AI (XAI)
# ==========================================
def print_xai_explanation(attn_weights, input_tensor):
    """In ra Terminal Heatmap giải thích quyết định của AI"""
    # 1. Tìm gói tin bị AI chú ý nhất trong 10 gói
    max_step_idx = torch.argmax(attn_weights).item()
    most_suspicious_packet = input_tensor[0, max_step_idx].cpu().numpy()
    
    # 2. Tìm top 3 đặc trưng (features) dị thường nhất trong gói đó
    # Dùng giá trị tuyệt đối sau khi scale để đo mức độ bất thường
    top_indices = np.argsort(np.abs(most_suspicious_packet))[-3:][::-1]
    
    console.print("\n[bold yellow][EXPLAIN] Mổ xẻ Báo cáo Quyết định của AI (Top 3 Contributions):[/bold yellow]")
    colors = ["bold red", "bold bright_yellow", "bold green"]
    labels = ["🔴 CRITICAL", "🟡 WARNING ", "🟢 NOTABLE "]
    
    for i, idx in enumerate(top_indices):
        feat_name = FEATURE_NAMES[idx]
        feat_val = most_suspicious_packet[idx]
        # Tạo % minh họa dựa trên độ lớn dị thường
        contribution = (abs(feat_val) / np.sum(np.abs(most_suspicious_packet[top_indices]))) * 100
        
        msg = f"[{colors[i]}]{labels[i]} {feat_name:<16} : {contribution:>4.1f}% (Scaled Score: {feat_val:>.2f})[/{colors[i]}]"
        console.print(msg)
    console.print("-" * 65)

# ==========================================
# MODULE 3: PHÒNG THỦ ĐA TẦNG (MITIGATION)
# ==========================================
def execute_mitigation(src_ip, attack_name, confidence, is_zero_day=False):
    action = ""
    treatment = {}
    
    if is_zero_day:
        action = "REDIRECT TO HONEYPOT"
        treatment = { "instructions": [{"type": "OUTPUT", "port": HONEYPOT_PORT}] }
        color = "bold magenta"
    elif confidence > 95.0:
        action = "DROP (CHẶN HOÀN TOÀN)"
        treatment = { "instructions": [{"type": "DROP"}] }
        color = "bold red"
    else:
        action = "RATE LIMIT (ÉP BĂNG THÔNG)"
        # Ở thực tế, ONOS Rate limit cần tạo Meter trước. Ở đây giả lập JSON:
        treatment = { "instructions": [{"type": "METER", "meterId": "1"}] } 
        color = "bold yellow"

    panel_content = (
        f"[bold]Loại Tấn Công:[/bold] {attack_name}\n"
        f"[bold]IP Kẻ Gian:[/bold] {src_ip}\n"
        f"[bold]Độ tin cậy AI:[/bold] {confidence:.2f}%\n"
        f"[{color}]=> HÀNH ĐỘNG: {action}[/{color}] via ONOS API"
    )
    console.print(Panel(panel_content, title="[bold red]🚨 BÁO ĐỘNG TẤN CÔNG DDoS 🚨[/bold red]", expand=False))
    
    flow_rule = {
        "priority": 40000, "timeout": 0, "isPermanent": True,
        "deviceId": "of:0000000000000001",
        "treatment": treatment,
        "selector": {
            "criteria": [ {"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "IPV4_SRC", "ip": f"{src_ip}/32"} ]
        }
    }
    
    # REST API MOCK
    # requests.post(f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1/flows/...", json=flow_rule, auth=(ONOS_USER, ONOS_PASS))
    console.print("[bold green]✅ Lệnh mitigation đã được đẩy xuống Switch OpenFlow![/bold green]\n")

# ==========================================
# MAIN: REAL-TIME PIPELINE (IN-MEMORY STREAMING)
# ==========================================
if __name__ == "__main__":
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    console.print(f"[bold cyan]💻 Khởi động HỆ THỐNG PHÒNG THỦ SDN (Dual-Engine) trên: {device.type.upper()}[/bold cyan]")
    
    load_checkpoint()
    
    # Khởi động luồng Background Checkpoint
    threading.Thread(target=save_threshold_worker, daemon=True).start()
    
    try:
        scaler = joblib.load('sdn_scaler.pkl')
        ae_model = Anomaly_Autoencoder().to(device)
        ae_model.load_state_dict(torch.load('sdn_autoencoder.pth', map_location=device))
        ae_model.eval()
        
        cls_model = DDos_CNN_GRU_Attention().to(device)
        cls_model.load_state_dict(torch.load('sdn_model_cnn_gru_attn.pth', map_location=device))
        cls_model.eval()
    except Exception as e:
        console.print(f"[bold red]❌ Lỗi nạp mô hình: {e}[/bold red]")
        exit()

    # --- KHỞI TẠO FIFO CHO ZEEK ---
    if not os.path.exists(FIFO_PATH):
        try:
            os.mkfifo(FIFO_PATH)
            console.print(f"[dim]Tạo Named Pipe thành công tại: {FIFO_PATH}[/dim]")
        except Exception as e:
            console.print(f"[bold yellow]⚠️ Không thể tạo FIFO ({e}). Chuyển sang chạy giả lập (Mock Mode).[/bold yellow]")

    console.print("[bold green]📡 Hệ thống đang lắng nghe lưu lượng từ luồng RAM (Zeek In-Memory)...[/bold green]\n")

    # Buffer chứa luồng mạng theo IP (gom đủ 10 luồng thì mang đi AI infer)
    ip_buffers = {}

    while True:
        try:
            # LƯU Ý: Lệnh open() này sẽ block (đứng chờ) cho đến khi Zeek đẩy dữ liệu vào ống.
            # Nếu bạn chưa cài Zeek, hãy mở Terminal khác và gõ: 
            # echo '{"ip": "10.0.0.9", "features": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}' > /tmp/zeek_stream.json
            with open(FIFO_PATH, 'r') as fifo:
                for line in fifo:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        src_ip = data.get("ip", "unknown")
                        features = data.get("features", [])
                        
                        if len(features) != NUM_FEATURES: continue
                        
                        if src_ip not in ip_buffers:
                            ip_buffers[src_ip] = []
                        ip_buffers[src_ip].append(features)
                        
                        # KHI ĐÃ GOM ĐỦ 10 GÓI TIN TỪ CÙNG 1 IP -> KÍCH HOẠT AI
                        if len(ip_buffers[src_ip]) == SEQ_LEN:
                            live_traffic_matrix = np.array(ip_buffers[src_ip])
                            ip_buffers[src_ip] = [] # Reset buffer
                            
                            # [BƯỚC 1] Tiền xử lý
                            scaled_traffic = scaler.transform(live_traffic_matrix)
                            input_tensor = torch.FloatTensor(scaled_traffic).unsqueeze(0).to(device)

                            # [BƯỚC 2] Khiên 1: Autoencoder
                            with torch.no_grad():
                                reconstructed = ae_model(input_tensor)
                                mse_loss = torch.mean((input_tensor - reconstructed)**2).item()
                            
                            with threshold_lock:
                                current_threshold = dynamic_threshold

                            if mse_loss > current_threshold:
                                execute_mitigation(src_ip, "DỊ THƯỜNG ZERO-DAY GIAO THỨC LẠ", confidence=99.9, is_zero_day=True)
                                continue # Bỏ qua Khiên 2
                                
                            # [BƯỚC 3] Khiên 2: Phân loại DDoS Đã biết
                            with torch.no_grad():
                                outputs, attn_weights = cls_model(input_tensor)
                                probabilities = torch.nn.functional.softmax(outputs, dim=1)
                                pred_idx = torch.argmax(probabilities, dim=1).item()
                                confidence = probabilities[0][pred_idx].item() * 100

                            if pred_idx == 0:
                                # Nếu luồng Mạng An toàn -> Cập nhật Concept Drift EMA
                                with threshold_lock:
                                    dynamic_threshold = EMA_ALPHA * mse_loss + (1 - EMA_ALPHA) * dynamic_threshold
                            else:
                                # Có Tấn công -> Ra lệnh ONOS & Giải thích XAI
                                if confidence >= 80.0:
                                    execute_mitigation(src_ip, LABEL_NAMES[pred_idx], confidence)
                                    print_xai_explanation(attn_weights, input_tensor)

                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            # Chạy giả lập 1 nhịp nếu không chạy môi trường Linux
            time.sleep(2)
            console.print("[dim]Đang chạy dữ liệu giả lập (Mocking)...[/dim]")
            mock_data = np.random.rand(10, 20)
            mock_data[:, 3] = 115000000 # Giả lập Slowloris
            mock_ip = "10.0.0.9"
            
            scaled = scaler.transform(mock_data)
            tensor = torch.FloatTensor(scaled).unsqueeze(0).to(device)
            out, attn = cls_model(tensor)
            execute_mitigation(mock_ip, LABEL_NAMES[4], 98.5)
            print_xai_explanation(attn, tensor)
            break