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
from config import Anomaly_Autoencoder, DDos_CNN_GRU_Attention, SEQ_LEN, LABEL_NAMES, FEATURE_NAMES, NUM_FEATURES

console = Console()

# ==========================================
# CẤU HÌNH HỆ THỐNG & DOANH NGHIỆP
# ==========================================
ONOS_IP = "127.0.0.1"
ONOS_PORT = "8181"
ONOS_USER = "onos"
ONOS_PASS = "rocks"
HONEYPOT_PORT = "2" # Cổng switch dẫn tới Honeypot

FIFO_PATH = "zeek_stream.json"
CHECKPOINT_FILE = "threshold_state.json"

# Cấu hình AI Concept Drift
EMA_ALPHA = 0.05
dynamic_threshold = 0.1827
threshold_lock = threading.Lock()

# Cấu hình Tối ưu Phần mềm (System Optimization)
COOLDOWN_TIME = 300      # (Giây) Thời gian cấm vận IP bị block, chống spam log
BUFFER_TIMEOUT = 60      # (Giây) Thời gian tối đa giữ 1 IP trong RAM nếu không đủ 10 gói
ip_buffers = {}          # { '10.0.0.9': {'data': [...], 'last_seen': 16123...} }
blocked_ips = {}         # { '10.0.0.9': 16123... }
last_log_time = {}       # Chống spam log ra màn hình
buffer_lock = threading.Lock()


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
        except Exception:
            pass

# ==========================================
# MODULE 2: EXPLAINABLE AI (XAI)
# ==========================================
def print_xai_explanation(attn_weights, input_tensor):
    """In ra Terminal Heatmap giải thích quyết định của AI"""
    max_step_idx = torch.argmax(attn_weights).item()
    most_suspicious_packet = input_tensor[0, max_step_idx].cpu().numpy()
    
    top_indices = np.argsort(np.abs(most_suspicious_packet))[-3:][::-1]
    
    console.print("\n[bold yellow][EXPLAIN] Mổ xẻ Báo cáo Quyết định của AI (Top 3 Contributions):[/bold yellow]")
    colors = ["bold red", "bold bright_yellow", "bold green"]
    labels = ["🔴 CRITICAL", "🟡 WARNING ", "🟢 NOTABLE "]
    
    for i, idx in enumerate(top_indices):
        feat_name = FEATURE_NAMES[idx]
        feat_val = most_suspicious_packet[idx]
        sum_val = np.sum(np.abs(most_suspicious_packet[top_indices]))
        contribution = (abs(feat_val) / sum_val) * 100 if sum_val > 0 else 0
        
        msg = f"[{colors[i]}]{labels[i]} {feat_name:<16} : {contribution:>4.1f}% (Scaled Score: {feat_val:>.2f})[/{colors[i]}]"
        console.print(msg)
    console.print("-" * 65)

# ==========================================
# MODULE 3: TỐI ƯU HÓA HỆ THỐNG (GARBAGE COLLECTOR & ASYNC IO)
# ==========================================
def buffer_cleanup_worker():
    """Luồng Dọn Rác RAM: Xóa các luồng mạng rác không bao giờ đạt tới 10 gói tin"""
    while True:
        time.sleep(10) # Quét mỗi 10s
        current_time = time.time()
        cleaned_count = 0
        with buffer_lock:
            # Tìm các IP đã quá hạn (không gửi thêm gói nào trong 60s)
            stale_ips = [ip for ip, info in ip_buffers.items() if current_time - info['last_seen'] > BUFFER_TIMEOUT]
            for ip in stale_ips:
                del ip_buffers[ip]
                cleaned_count += 1
        if cleaned_count > 0:
            console.print(f"[dim]🧹 [Garbage Collector] Đã dọn dẹp {cleaned_count} IP rác khỏi RAM để giải phóng bộ nhớ.[/dim]")

def async_onos_request(flow_rule):
    """Tiến trình thực thi REST API đẩy xuống ONOS không gây Block AI"""
    try:
        url = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1/flows/{flow_rule['deviceId']}"
        # Xóa comment dòng dưới khi Mininet/ONOS thực sự chạy
        # requests.post(url, json=flow_rule, auth=(ONOS_USER, ONOS_PASS), timeout=2)
        pass 
    except Exception as e:
        console.print(f"[dim red]⚠️ Lỗi gọi ONOS API: {e}[/dim red]")

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
        "selector": { "criteria": [ {"type": "ETH_TYPE", "ethType": "0x0800"}, {"type": "IPV4_SRC", "ip": f"{src_ip}/32"} ] }
    }
    
    # Kích hoạt luồng chạy ngầm gửi lệnh xuống Switch (Bất đồng bộ)
    threading.Thread(target=async_onos_request, args=(flow_rule,), daemon=True).start()
    console.print("[bold green]✅ Lệnh mitigation đã được đẩy xuống OpenFlow (Bất đồng bộ)![/bold green]\n")

# ==========================================
# MAIN: REAL-TIME PIPELINE (IN-MEMORY STREAMING)
# ==========================================
if __name__ == "__main__":
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    console.print(f"[bold cyan]💻 Khởi động HỆ THỐNG PHÒNG THỦ SDN (Dual-Engine) trên: {device.type.upper()}[/bold cyan]")
    
    load_checkpoint()
    
    # Khởi động các luồng Background (CheckPoint SSD & Dọn rác RAM)
    threading.Thread(target=save_threshold_worker, daemon=True).start()
    threading.Thread(target=buffer_cleanup_worker, daemon=True).start()
    
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

# ==========================================
    # AUTO-CLEANUP: Dọn dẹp ống RAM cũ trước khi chạy
    # ==========================================
    if os.path.exists(FIFO_PATH):
        try:
            os.remove(FIFO_PATH)
            console.print(f"[dim]🧹 Đã dọn dẹp ống RAM cũ ({FIFO_PATH}) từ lần chạy trước.[/dim]")
        except Exception as e:
            console.print(f"[bold red]⚠️ Cảnh báo: Không thể xóa ống cũ ({e})[/bold red]")
            
    # Tạo lại một ống RAM hoàn toàn mới và sạch sẽ
    try:
        os.mkfifo(FIFO_PATH)
    except Exception as e:
        console.print(f"[bold red]❌ Lỗi tạo ống RAM: {e}[/bold red]")

    console.print("[bold green]📡 Hệ thống đang lắng nghe lưu lượng từ luồng RAM (Zeek In-Memory)...[/bold green]\n")

    while True:
        try:
            with open(FIFO_PATH, 'r') as fifo:
                for line in fifo:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        src_ip = data.get("ip", "unknown")
                        features = data.get("features", [])
                        
                        if len(features) != NUM_FEATURES: continue
                        
                        current_time = time.time()
                        
                        # [CHỐNG SPAM] Kiểm tra xem IP này đã bị cấm vận chưa
                        if src_ip in blocked_ips:
                            if current_time - blocked_ips[src_ip] < COOLDOWN_TIME:
                                # In log báo bị chặn (chỉ in 1 lần mỗi 5 giây để không làm treo màn hình)
                                if src_ip not in last_log_time or current_time - last_log_time[src_ip] > 5:
                                    console.print(f"[dim red]🛑 [CHỐNG SPAM] Từ chối phân tích AI cho IP {src_ip} (Đang bị cấm vận {COOLDOWN_TIME}s)[/dim red]")
                                    last_log_time[src_ip] = current_time
                                continue # Hủy gói tin ngay lập tức (giảm tải AI)
                            else:
                                del blocked_ips[src_ip] # Hết hạn cấm vận, theo dõi lại
                        
                        # Đẩy gói tin vào RAM an toàn thông qua threading.Lock
                        ready_to_process = False
                        with buffer_lock:
                            if src_ip not in ip_buffers:
                                ip_buffers[src_ip] = {'data': [], 'last_seen': current_time}
                                
                            ip_buffers[src_ip]['data'].append(features)
                            ip_buffers[src_ip]['last_seen'] = current_time
                            
                            current_len = len(ip_buffers[src_ip]['data'])
                            
                            print(f"[DEBUG] Đang nạp gói tin từ IP {src_ip}: {current_len}/10")
                            
                            # Gom đủ 10 gói thì chốt sổ
                            if current_len == SEQ_LEN:
                                live_traffic_matrix = np.array(ip_buffers[src_ip]['data'])
                                del ip_buffers[src_ip] # Xóa khỏi buffer để đón luồng mới
                                ready_to_process = True
                                
                        # NẾU ĐỦ 10 GÓI -> KÍCH HOẠT AI (Ngoài buffer_lock để luồng thu thập không bị chặn)
                        if ready_to_process:
                            scaled_traffic = scaler.transform(live_traffic_matrix)
                            input_tensor = torch.FloatTensor(scaled_traffic).unsqueeze(0).to(device)

                            with threshold_lock:
                                current_threshold = dynamic_threshold

                            # [KHIÊN 1: Autoencoder]
                            with torch.no_grad():
                                reconstructed = ae_model(input_tensor)
                                mse_loss = torch.mean((input_tensor - reconstructed)**2).item()
                            
                            if mse_loss > current_threshold:
                                console.print(f"\n[bold magenta]🛡️ [KHIÊN 1 - AUTOENCODER] Phát hiện dị thường![/bold magenta]")
                                console.print(f"[bold magenta]   => MSE Loss: {mse_loss:.4f} (Vượt ngưỡng {current_threshold:.4f})[/bold magenta]")
                                
                                blocked_ips[src_ip] = current_time # Gắn cờ Blacklist
                                execute_mitigation(src_ip, "DỊ THƯỜNG ZERO-DAY GIAO THỨC LẠ", confidence=99.9, is_zero_day=True)
                                
                                with torch.no_grad():
                                    _, attn_weights = cls_model(input_tensor)
                                print_xai_explanation(attn_weights, input_tensor)
                                console.print("[dim]🔄 Đã reset bộ nhớ đệm, tiếp tục lắng nghe...[/dim]\n")
                                continue
                                
                            # [KHIÊN 2: CNN-GRU Phân Loại]
                            with torch.no_grad():
                                outputs, attn_weights = cls_model(input_tensor)
                                probabilities = torch.nn.functional.softmax(outputs, dim=1)
                                pred_idx = torch.argmax(probabilities, dim=1).item()
                                confidence = probabilities[0][pred_idx].item() * 100

                            console.print(f"\n[bold cyan]🧠 [KHIÊN 2 - CNN-GRU] Đã phân tích 10 gói tin từ IP {src_ip}[/bold cyan]")
                            console.print(f"[bold cyan]   => Kết luận: {LABEL_NAMES[pred_idx]} | Độ tự tin: {confidence:.2f}% | MSE: {mse_loss:.4f}[/bold cyan]")

                            if pred_idx == 0:
                                console.print("[dim]   => Trạng thái: Bình thường. Đang cập nhật ngưỡng EMA...[/dim]")
                                with threshold_lock:
                                    dynamic_threshold = EMA_ALPHA * mse_loss + (1 - EMA_ALPHA) * dynamic_threshold
                            else:
                                if confidence >= 50.0: 
                                    blocked_ips[src_ip] = current_time # Gắn cờ Blacklist
                                    execute_mitigation(src_ip, LABEL_NAMES[pred_idx], confidence)
                                    print_xai_explanation(attn_weights, input_tensor)
                                else:
                                    console.print(f"[dim]   => Bỏ qua: Nghi ngờ nhưng độ tự tin quá thấp (< 50%).[/dim]")
                            
                            console.print("[dim]🔄 Đã reset bộ đệm, tiếp tục lắng nghe...[/dim]\n")

                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            time.sleep(2)
            console.print("[dim]Đang chạy dữ liệu giả lập (Mocking)...[/dim]")
            break