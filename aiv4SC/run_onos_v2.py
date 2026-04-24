#!/usr/bin/env python3
"""
Tên file: run_onos_v2.py (hoặc upgrade cho run_onos.py)
Phiên bản: 2.1 (Production-ready with enhanced logging)

Mô tả:
  IDS Engine v2.1 - AI-based DDoS Detection + SDN Mitigation
  - Load AI v2 models (Autoencoder + Classifier)
  - Real-time flow processing from FIFO
  - Adaptive threshold (EMA-based)
  - Advanced XAI explanations
  - SDN rule injection (ONOS/OVS)
  - Production logging

Tương thích: config_v2.py + train_colab_v2.py models
"""

import torch
import numpy as np
import joblib
import time
import requests
import json
import os
import threading
import logging
import warnings
from pathlib import Path

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# =====================================================================
# IMPORT FROM AI V2
# =====================================================================
from config_v2 import (
    AIModelManager, SDN_XAI_Explainer_Advanced, SEQ_LEN, LABEL_NAMES,
    FEATURE_NAMES, NUM_FEATURES_TOTAL, NUM_CLASSES
)

warnings.filterwarnings("ignore")
console = Console()

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# =====================================================================
# LOGGING SETUP (Production)
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ids_engine_v2.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("IDS_V2")

# =====================================================================
# CONFIGURATION
# =====================================================================

class SDNConfigV2:
    """Enhanced SDN Configuration for v2.1"""
    
    # ONOS REST API
    ONOS_URL = os.environ.get("ONOS_URL", "http://127.0.0.1:8181/onos/v1")
    ONOS_AUTH = (
        os.environ.get("ONOS_USER", "onos"),
        os.environ.get("ONOS_PASS", "rocks")
    )
    
    # OVS Switch IDs
    CORE_SWITCH_ID = os.environ.get("CORE_SWITCH_ID", "of:0000000000000001")           # S1: Core Switch
    HONEYPOT_PORT = os.environ.get("HONEYPOT_PORT", "2")
    
    # FIFO Paths (Dual mode)
    FIFO_PATH_NORMAL = os.environ.get("FIFO_NORMAL", "zeek_stream.json")
    FIFO_PATH_SLOWLORIS = os.environ.get("FIFO_SLOWLORIS", "zeek_stream_slowloris.json")
    FIFO_MARKER_NORMAL = ".marker_normal"
    FIFO_MARKER_SLOWLORIS = ".marker_slowloris"
    
    # Checkpoint (Lưu tại thư mục gốc của script AI)
    CHECKPOINT_FILE = os.environ.get("CHECKPOINT_FILE", "threshold_state.json")
    
    # Whitelist (INFRA_SUBNET - never block)
    WHITELIST = [
        "10.0.0.10", "10.0.0.11", "10.0.0.20",
        "10.0.0.100", "10.0.0.101", "10.0.0.102"
    ]
    INFRA_PREFIX = "10.0.0."
    
    # AI Logic
    EMA_ALPHA = 0.02  # Giảm từ 0.05 xuống 0.02 để ngưỡng thay đổi chậm và ổn định hơn
    COOLDOWN_TIME = int(os.environ.get("COOLDOWN_TIME", "300"))      # 5 min
    BUFFER_TIMEOUT = int(os.environ.get("BUFFER_TIMEOUT", "60"))     # 1 min
    MAX_CONCURRENT_IPS = int(os.environ.get("MAX_IPS", "1000"))      # Max IPs
    
    # AI Model paths
    MODEL_BASE_PATH = os.environ.get("AI_MODEL_PATH", "")
    
    @staticmethod
    def detect_current_fifo():
        """Auto-detect which FIFO to read based on marker files"""
        if os.path.exists(SDNConfigV2.FIFO_MARKER_SLOWLORIS):
            return SDNConfigV2.FIFO_PATH_SLOWLORIS
        elif os.path.exists(SDNConfigV2.FIFO_MARKER_NORMAL):
            return SDNConfigV2.FIFO_PATH_NORMAL
        else:
            if os.path.exists(SDNConfigV2.FIFO_PATH_SLOWLORIS):
                return SDNConfigV2.FIFO_PATH_SLOWLORIS
            else:
                return SDNConfigV2.FIFO_PATH_NORMAL
    
    @classmethod
    def validate(cls):
        """Validate config at startup"""
        logger.info(f"[CONFIG] ONOS URL: {cls.ONOS_URL}")
        logger.info(f"[CONFIG] Model Path: {cls.MODEL_BASE_PATH}")
        logger.info(f"[CONFIG] EMA Alpha: {cls.EMA_ALPHA}")
        logger.info(f"[CONFIG] Cooldown: {cls.COOLDOWN_TIME}s")

# =====================================================================
# SDN CONTROLLER MODULE
# =====================================================================
class SDNControllerV2:
    
    @staticmethod
    def push_flow_rule(src_ip, treatment_type="DROP"):
        """Push flow rule to ONOS"""
        
        if treatment_type == "DROP":
            instructions = []  
        elif treatment_type == "HONEYPOT":
            instructions = [{"type": "OUTPUT", "port": SDNConfigV2.HONEYPOT_PORT}]
        elif treatment_type == "RATE_LIMIT":
            instructions = [{"type": "METER", "meterId": "1"}]
        else:
            instructions = []  # Mặc định an toàn là DROP
        
        flow_rule = {
            "priority": 40000,
            "timeout": 300,            # Tự động xóa sau 300 giây (5 phút) để tránh tràn TCAM
            "isPermanent": False,      # KHÔNG vĩnh viễn
            "deviceId": SDNConfigV2.CORE_SWITCH_ID,
            "treatment": {"instructions": instructions},
            "selector": {
                "criteria": [
                    {"type": "ETH_TYPE", "ethType": "0x0800"},
                    {"type": "IPV4_SRC", "ip": f"{src_ip}/32"}
                ]
            }
        }
        
        url = f"{SDNConfigV2.ONOS_URL}/flows/{SDNConfigV2.CORE_SWITCH_ID}"
        
        # 2. HÀM KIỂM TRA PHẢN HỒI TỪ ONOS
        def send_request():
            try:
                response = requests.post(url, json=flow_rule, auth=SDNConfigV2.ONOS_AUTH, timeout=3)
                # Kiểm tra xem ONOS có chấp nhận lệnh không (HTTP 200, 201, 202)
                if response.status_code in [200, 201, 202]:
                    logger.info(f"[SDN] Thành công: Luật {treatment_type} đã cắm cho IP {src_ip} tại {SDNConfigV2.CORE_SWITCH_ID}")
                else:
                    logger.error(f"[SDN LỖI API] ONOS từ chối! Code: {response.status_code}, Phản hồi: {response.text}")
            except Exception as e:
                logger.error(f"[SDN LỖI MẠNG] Không thể kết nối tới ONOS: {e}")

        # Chạy hàm send_request bằng luồng ngầm để không block AI
        threading.Thread(target=send_request, daemon=True).start()
        return True

# =====================================================================
# IDS ENGINE V2.1 (MAIN)
# =====================================================================

class IDSEngineV2:
    """Advanced IDS Engine with AI v2 models"""
    
    def __init__(self):
        logger.info("[IDS] Initializing IDS Engine v2.1...")
        
        # Load AI pipeline
        self.pipeline = AIModelManager.load_full_pipeline(SDNConfigV2.MODEL_BASE_PATH)
        if not self.pipeline:
            logger.critical("[IDS] Failed to load AI pipeline!")
            raise RuntimeError("Pipeline load failed")
        
        # XAI explainer
        self.explainer = SDN_XAI_Explainer_Advanced(feature_names=FEATURE_NAMES)
        
        # Thresholds
        self.base_threshold = self.pipeline["threshold"]
        self.dynamic_threshold = self.base_threshold
        
        # 1. PHỤC HỒI V1: Nạp "Trí nhớ" từ lần chạy trước & Đảm bảo giá trị MIN
        checkpoint_path = SDNConfigV2.CHECKPOINT_FILE
        if os.path.exists(checkpoint_path):
            try:
                with open(checkpoint_path, 'r') as f:
                    data = json.load(f)
                    saved_th = data.get('threshold', self.base_threshold)
                    
                    # GIÁ TRỊ MIN: Dù quá khứ rảnh rỗi thế nào, ngưỡng không được thấp hơn Sàn (ví dụ: 90% base_threshold)
                    min_allowed_threshold = self.base_threshold * 0.9
                    self.dynamic_threshold = max(saved_th, min_allowed_threshold)
                    
                logger.info(f"[CHECKPOINT] Đã nạp trí nhớ cũ! Ngưỡng: {self.dynamic_threshold:.4f} (Min Sàn: {min_allowed_threshold:.4f})")
            except Exception as e:
                logger.error(f"[CHECKPOINT] Lỗi đọc trí nhớ: {e}")

        # Buffers
        self.ip_buffers = {}
        self.mse_history = []
        self.mse_ema = {} # Lưu trữ EMA của MSE cho từng IP để làm mượt nhiễu
        self._last_log_th = self.dynamic_threshold
        
        # Stats & Lock
        self.stats = {
            "processed": 0,
            "blocked": 0,
            "avg_latency_ms": 0,
            "zero_day": 0,
            "blocked_ips": {}  # Đổi từ set sang dict để lưu timestamp {ip: timestamp}
        }
        self.lock = threading.Lock()

        # 2. Bật lại luồng chạy ngầm để lưu trạng thái (Save Worker)
        threading.Thread(target=self._save_threshold_worker, daemon=True).start()
        
        # Cấu hình đường dẫn lưu Feedback Loop
        self.feedback_dir = "potential_false_positives"
        if not os.path.exists(self.feedback_dir):
            os.makedirs(self.feedback_dir)
        
        # [V7] Load feature weights nếu có
        self.feature_weights = self._load_feature_weights()
        
        logger.info(f"[IDS] Engine ready on device: {self.pipeline['device']}")
        logger.info(f"[IDS] Base threshold: {self.base_threshold:.4f}")
    
    def _load_feature_weights(self):
        """Load feature weights từ training nếu có, nếu không dùng default"""
        try:
            import joblib
            weights = joblib.load(os.path.join(SDNConfigV2.MODEL_BASE_PATH, 'feature_weights.pkl'))
            logger.info("[V7] Đã load feature weights từ training")
            return weights
        except:
            # Default weights nếu không có file
            weights = np.ones(NUM_FEATURES_TOTAL)
            weights[3] = 2.0    # Duration
            weights[16] = 2.0   # d_Duration
            weights[10] = 2.0   # Packet_Rate
            weights[23] = 2.0   # d_Packet_Rate
            weights[11] = 1.5   # Byte_Rate
            weights[24] = 1.5   # d_Byte_Rate
            weights[0] = 0.5    # Src_Port_Entropy
            weights[1] = 0.5    # Dst_Port_Entropy
            weights[13] = 0.5   # d_Src_Port_Entropy
            weights[14] = 0.5   # d_Dst_Port_Entropy
            logger.info("[V7] Sử dụng default feature weights")
            return weights
    
    def _save_threshold_worker(self):
        """Luồng ngầm lưu ngưỡng xuống SSD (Giống v1)"""
        while True:
            time.sleep(60) # Cứ 60 giây lưu 1 lần
            with self.lock:
                current_th = self.dynamic_threshold
            try:
                os.makedirs(os.path.dirname(SDNConfigV2.CHECKPOINT_FILE), exist_ok=True)
                with open(SDNConfigV2.CHECKPOINT_FILE, 'w') as f:
                    json.dump({'threshold': current_th, 'timestamp': time.time()}, f)
            except Exception:
                pass

    def dynamic_threshold_update(self, mse_score):
        """Update threshold adaptively using EMA & Min Bound"""
        with self.lock:
            self.mse_history.append(mse_score)
            if len(self.mse_history) > 100:
                self.mse_history.pop(0)
            
            recent_mse = np.array(self.mse_history)
            mean_mse = np.mean(recent_mse)
            std_mse = np.std(recent_mse)
            
            # NỚI LỎNG KHIÊN 1: Tăng k_factor từ 3.5 lên 4.5
            # Mức 4.5 giúp loại bỏ hầu như toàn bộ nhiễu mạng (False Positives)
            k_factor = 4.5  
            new_threshold = mean_mse + (k_factor * std_mse)
            
            self.dynamic_threshold = (
                SDNConfigV2.EMA_ALPHA * new_threshold +
                (1 - SDNConfigV2.EMA_ALPHA) * self.dynamic_threshold
            )
            
            # 3. GIÁ TRỊ MIN/MAX CỐ ĐỊNH CHỐNG ẢO GIÁC
            # Đẩy Min Floor lên cao hơn (1.2x base) để Khiên 1 không bao giờ quá khắt khe
            min_floor = self.base_threshold * 1.2  
            max_ceil = self.base_threshold * 5.0   
            
            self.dynamic_threshold = np.clip(self.dynamic_threshold, min_floor, max_ceil)
            
            # [FIX] Giảm log spam - chỉ log khi thay đổi >20% và tối đa 1 lần/30s
            current_time = time.time()
            last_log_time = getattr(self, '_last_adapt_log_time', 0)
            threshold_change_pct = abs(self.dynamic_threshold - getattr(self, '_last_log_th', 0)) / self.base_threshold
            
            if threshold_change_pct > 0.20 and (current_time - last_log_time) > 30:
                logger.info(f"[ADAPT] Threshold: {self.base_threshold:.4f} → {self.dynamic_threshold:.4f} ({threshold_change_pct*100:+.1f}%)")
                self._last_log_th = self.dynamic_threshold
                self._last_adapt_log_time = current_time
    
    def execute_mitigation(self, src_ip, attack_name, confidence, is_zero_day=False):
        """Level 2 Mitigation: Chặn hoàn toàn (DROP) via ONOS REST API"""
        if src_ip in self.stats["blocked_ips"]:
            return

        # [FIX] Dùng ONOS REST API thay vì ovs-ofctl trực tiếp
        SDNControllerV2.push_flow_rule(src_ip, treatment_type="DROP")
        
        self.stats["blocked_ips"][src_ip] = time.time()
        self.stats["blocked"] += 1
        if is_zero_day: self.stats["zero_day"] += 1
        
        self.log_attack_panel(src_ip, attack_name, confidence, "DROP", "red")
        logger.error(f"[IPS] 🛡️ Đã thực thi lệnh DROP cho IP {src_ip} qua ONOS.")
    def apply_rate_limit(self, src_ip):
        """[LEVEL 1 MITIGATION] Giới hạn băng thông (1Mbps) via ONOS"""
        # [FIX] Dùng ONOS REST API thay vì ovs-ofctl
        SDNControllerV2.push_flow_rule(src_ip, treatment_type="RATE_LIMIT")
        logger.warning(f"[MITIGATION] Level 1: Đã áp dụng Rate Limit cho {src_ip} qua ONOS")
        
    def apply_honeypot_redirect(self, src_ip):
        """
        [PHƯƠNG ÁN CŨ] Chuyển hướng sang Honeypot
        Đã chuyển sang dùng Rate Limit ở Level 1 để chuyên nghiệp hơn.
        """
        # cmd = f"ovs-ofctl add-flow s6 'priority=35000,ip,nw_src={src_ip},actions=mod_nw_dst:10.0.0.201,normal'"
        # os.system(cmd)
        # logger.warning(f"[MITIGATION] Đã chuyển hướng {src_ip} sang Honeypot (10.0.0.201)")
        pass

    def log_attack_panel(self, src_ip, attack_name, confidence, action_str, color_str):
        """Hiển thị thông báo tấn công lên console"""
        msg = f"[bold]IP:[/bold] {src_ip}\n"
        msg += f"[bold]Type:[/bold] {attack_name}\n"
        msg += f"[bold]Confidence:[/bold] {confidence:.1f}%\n"
        msg += f"[bold]Action:[/bold] [{color_str}]{action_str}[/{color_str}]"
        console.print(Panel(msg, title="🚨 [bold red]IDS ALERT[/bold red]", expand=False))
        
    def log_normal_panel(self, src_ip, normal_prob, mse, threshold):
        """[NEW] Hiển thị thông báo Normal chi tiết 2 khiên"""
        msg = f"[bold]IP:[/bold] {src_ip}\n"
        msg += f"[bold]Classification:[/bold] [green]BENIGN[/green] ({normal_prob:.1f}%)\n"
        msg += f"[bold]Shield 1 (AE):[/bold] MSE={mse:.4f} | Threshold={threshold:.4f} | Status={'✅ Normal' if mse < threshold else '⚠️ Anomaly (Ignored)'}\n"
        msg += f"[bold]Shield 2 (CLS):[/bold] Normal={normal_prob:.1f}% | Status={'✅ Confident' if normal_prob > 80 else '⚠️ Uncertain'}\n"
        msg += f"[bold]Action:[/bold] [green]ALLOW[/green]"
        console.print(Panel(msg, title="✅ [bold green]NORMAL TRAFFIC[/bold green]", expand=False))
            
    def save_to_feedback_loop(self, src_ip, sequence_data, metadata):
        """Lưu lại các mẫu bị Veto để tái huấn luyện (Active Learning)"""
        import json
        filename = f"{self.feedback_dir}/veto_{int(time.time())}_{src_ip.replace('.', '_')}.json"
        data = {
            "src_ip": src_ip,
            "sequence": sequence_data.tolist(),
            "metadata": metadata
        }
        with open(filename, 'w') as f:
            json.dump(data, f)
        logger.info(f"[FEEDBACK] Đã lưu mẫu Veto của {src_ip} để Active Learning.")

    def apply_rate_limit(self, src_ip):
        """Level 1 Mitigation: Giới hạn băng thông (Rate Limit) thay vì Honeypot"""
        # Giả định OVS đã được cấu hình meter (meter id 1: 1Mbps)
        # Nếu chưa cấu hình meter, lệnh này sẽ không lỗi nhưng không có tác dụng cho đến khi cấu hình
        cmd = f"ovs-ofctl add-flow s6 'priority=35000,ip,nw_src={src_ip},actions=meter:1,normal'"
        os.system(cmd)
        logger.warning(f"[MITIGATION] Level 1: Đã áp dụng Rate Limit (1Mbps) cho {src_ip}")

    def process_sequence(self, src_ip, sequence):
        """Process a single sequence (10 flows)"""
        start_time = time.time()
        
        # Bỏ qua nếu là 2 chuỗi đầu tiên của mỗi IP (Warm-up phase)
        # Điều này giúp tránh bắt nhầm traffic lỗi lúc server đang khởi động
        if not hasattr(self, 'ip_warmup_count'):
            self.ip_warmup_count = {}
        
        with self.lock:
            self.ip_warmup_count[src_ip] = self.ip_warmup_count.get(src_ip, 0) + 1
            if self.ip_warmup_count[src_ip] <= 2:
                logger.debug(f"[WARMUP] Skipping sequence for {src_ip} (Attempt {self.ip_warmup_count[src_ip]}/5)")
                return
        
        # Feature engineering: 13 → 26 (add differential)
        diff = np.zeros_like(sequence)  # [SEQ_LEN, 13]
        diff[1:, :] = sequence[1:, :] - sequence[:-1, :]
        
        # Combine original + differential
        seq_combined = np.concatenate([sequence, diff], axis=-1)  # [SEQ_LEN, 26]
        
        # LOG-TRANSFORM: Đồng bộ với train (Symmetry Log xử lý cả âm/dương)
        def safe_log_np(x):
            return np.sign(x) * np.log1p(np.abs(x))

        cols_to_log = [4, 5, 6, 7, 10, 11, 17, 18, 19, 20, 23, 24]
        seq_combined[:, cols_to_log] = safe_log_np(seq_combined[:, cols_to_log])
        
        # Xử lý NaN/Inf nếu phát sinh trong tính toán
        if np.any(np.isnan(seq_combined)) or np.any(np.isinf(seq_combined)):
            seq_combined = np.nan_to_num(seq_combined, nan=0.0)
        
        # [V7 UPDATE] Feature Importance Weighting (Đồng bộ với train_colab_v2)
        # Sử dụng self.feature_weights đã load từ file hoặc default
        seq_combined = seq_combined * self.feature_weights
        
        # Scaling (matches training pipeline)
        seq_flat = seq_combined.reshape(-1, NUM_FEATURES_TOTAL)
        seq_scaled = self.pipeline["scaler"].transform(seq_flat)
        seq_scaled = seq_scaled.reshape(SEQ_LEN, NUM_FEATURES_TOTAL)
        
        # Convert to tensor
        tensor = torch.FloatTensor(seq_scaled).unsqueeze(0).to(self.pipeline["device"])
        
        with torch.no_grad():
            # Autoencoder: anomaly detection
            recon, latent = self.pipeline["ae_model"](tensor)
            recon_flat = recon.view(recon.size(0), -1)
            tensor_flat = tensor.view(tensor.size(0), -1)
            mse_raw = torch.mean((tensor_flat - recon_flat) ** 2).item()
            
            # EMA cho MSE để làm mượt các đỉnh do nhiễu mạng (tránh False Zero-day)
            alpha_mse = 0.3
            if src_ip not in self.mse_ema:
                self.mse_ema[src_ip] = mse_raw
            else:
                self.mse_ema[src_ip] = (alpha_mse * mse_raw) + ((1 - alpha_mse) * self.mse_ema[src_ip])
            
            mse = self.mse_ema[src_ip]
            
            # Classifier: attack type
            logits, temporal_attn, spatial_weights = self.pipeline["cls_model"](tensor)
            probs = torch.softmax(logits, dim=1)
            pred_idx = torch.argmax(probs, dim=1).item()
            confidence = probs[0][pred_idx].item() * 100
        
        latency_ms = (time.time() - start_time) * 1000
        self.stats["avg_latency_ms"] = (self.stats["avg_latency_ms"] * 0.9) + (latency_ms * 0.1)
        
        # =====================================================================
        # [V7 UPDATE] Decision logic - 2 Shield Strategy (Bảo vệ Normal tuyệt đối)
        # =====================================================================
        self.stats["processed"] += 1
        is_attack = False
        is_zero_day = False
        
        # KHIÊN 1: Autoencoder phát hiện bất thường (MSE)
        is_anomaly = (mse > self.dynamic_threshold)

        # KHIÊN 2: Classifier phân loại (Confidence)
        normal_prob = probs[0][0].item() * 100
        attack_probs = probs[0][1:]
        top_attack_prob = torch.max(attack_probs).item() * 100
        top_attack_idx = torch.argmax(attack_probs).item() + 1  # +1 vì attack bắt đầu từ index 1

        # [CRITICAL] Bảo vệ Normal: Nếu Classifier nói là Normal (>80%) -> TIN NGAY
        if normal_prob > 80.0:
            # Shield 2 đã chắc chắn là Normal, bất chấp Shield 1 nói gì
            is_attack = False
            is_zero_day = False
            # [FIX] Hiển thị panel chi tiết 2 khiên cho Normal (mỗi 5 lần để tránh spam)
            if self.stats["processed"] % 5 == 0:
                self.log_normal_panel(src_ip, normal_prob, mse, self.dynamic_threshold)
        elif is_anomaly:
            # Shield 1 thấy bất thường, kiểm tra Shield 2
            if pred_idx != 0 and confidence > 85.0:
                # Shield 2 đồng ý là Attack với độ tin cao
                is_attack = True
                is_zero_day = False
            elif pred_idx == 0 and normal_prob < 30.0:
                # Shield 1 thấy bất thường, Shield 2 bối rối (Normal prob thấp)
                # -> Zero-Day (Attack mới chưa từng thấy)
                is_attack = True
                is_zero_day = True
                logger.warning(f"[ZERO-DAY] MSE cao ({mse:.4f}) nhưng Classifier không nhận diện được!")
            else:
                # Không đủ tin cậy -> Coi là bình thường (Conservative)
                is_attack = False
                logger.debug(f"[UNCERTAIN] AE anomaly nhưng Classifier không chắc chắn -> Bỏ qua")
        else:
            # Shield 1 thấy bình thường (MSE thấp)
            if pred_idx != 0 and confidence > 98.0:
                # Evasive Attack: Vượt qua AE nhưng Classifier phát hiện
                is_attack = True
                logger.warning(f"[EVASIVE] Phát hiện tấn công lẩn trốn: {LABEL_NAMES[pred_idx]} (Confidence {confidence:.1f}%)")
            else:
                # Bình thường
                is_attack = False
        
        if is_attack:
            # Phân tích mức độ nghiêm trọng
            # Level 2: Chặn hoàn toàn (Drop) nếu Confidence cực cao hoặc Zero-day rõ rệt
            if confidence > 98.0 or is_zero_day:
                decision = "DROP"
            else:
                # Level 1: Nghi ngờ nhưng chưa chắc chắn 100% -> Rate Limit
                decision = "RATE_LIMIT"

            attack_name = LABEL_NAMES[pred_idx] if not is_zero_day else "ZERO-DAY / VARIANT"
            if decision == "DROP":
                self.execute_mitigation(src_ip, attack_name, confidence, is_zero_day)
            elif decision == "RATE_LIMIT":
                self.apply_rate_limit(src_ip)
            
            # XAI explanation
            try:
                # Cập nhật logic XAI để hiểu được Zero-day
                if is_zero_day:
                    explanation_text = f"⚠️ CẢNH BÁO ZERO-DAY: Luồng dữ liệu có cấu trúc dị thường (MSE={mse:.4f}). AI không tìm thấy mẫu tương tự trong quá khứ."
                else:
                    # Lấy dictionary từ hàm explain_attack
                    xai_result = self.explainer.explain_attack(
                        tensor, temporal_attn, spatial_weights, pred_idx
                    )
                    # Trích xuất riêng phần chuỗi văn bản (String) để in ra màn hình
                    if isinstance(xai_result, dict):
                        explanation_text = xai_result.get("explanation_text", str(xai_result))
                    else:
                        explanation_text = str(xai_result)
                
                # Truyền chuỗi văn bản vào Panel
                console.print(Panel(explanation_text, title="📋 [bold cyan]XAI EXPLANATION[/bold cyan]", expand=False))
            except Exception as e:
                logger.error(f"[XAI ERROR] {e}")
        else:
            # Update threshold on benign
            if pred_idx == 0:
                self.dynamic_threshold_update(mse)
        
        self.stats["processed"] += 1
    
    def run(self):
        """Main detection loop"""
        console.print(f"[bold green]🚀 IDS Engine v2.1 Ready on {self.pipeline['device']}[/bold green]")
        console.print("[bold cyan]📡 Dual FIFO Mode: zeek_stream.json + zeek_stream_slowloris.json[/bold cyan]")
        
        last_fifo_check = 0
        current_fifo = SDNConfigV2.FIFO_PATH_NORMAL
        last_stats_print = time.time()
        last_cleanup = time.time() # Thêm biến theo dõi cleanup
        
        while True:
            try:
                now = time.time()
                
                # GC (Garbage Collector): Dọn rác IP_Buffers mỗi 10 giây để tránh Memory Leak
                if now - last_cleanup > 10.0:
                    with self.lock:
                        # 1. Dọn dẹp IP nhàn rỗi (sau 60s không có traffic)
                        stale_ips = [ip for ip, info in self.ip_buffers.items() if now - info["last"] > 60.0]
                        if stale_ips:
                            for ip in stale_ips:
                                del self.ip_buffers[ip]
                                if hasattr(self, 'ip_warmup_count') and ip in self.ip_warmup_count:
                                    del self.ip_warmup_count[ip]
                            logger.info(f"[GC] Đã dọn dẹp {len(stale_ips)} IP nhàn rỗi.")

                        # 2. Xử lý Spike Traffic: Nếu số lượng IP vượt 80% sức chứa, dọn dẹp khẩn cấp
                        # Xóa 20% các IP có traffic cũ nhất
                        MAX_IPS = 1000 # Giả định ngưỡng an toàn
                        if len(self.ip_buffers) > MAX_IPS * 0.8:
                            logger.warning(f"[GC] Spike Traffic! (IP count: {len(self.ip_buffers)}). Đang dọn dẹp khẩn cấp...")
                            sorted_ips = sorted(self.ip_buffers.items(), key=lambda x: x[1]["last"])
                            clear_count = int(len(self.ip_buffers) * 0.2)
                            for i in range(clear_count):
                                ip_to_del = sorted_ips[i][0]
                                del self.ip_buffers[ip_to_del]
                                if hasattr(self, 'ip_warmup_count') and ip_to_del in self.ip_warmup_count:
                                    del self.ip_warmup_count[ip_to_del]
                            logger.info(f"[GC] Đã xóa khẩn cấp {clear_count} IP cũ nhất để tránh tràn RAM.")

                    last_cleanup = now
                
                # Check FIFO switch every second
                if now - last_fifo_check > 1.0:
                    new_fifo = SDNConfigV2.detect_current_fifo()
                    if new_fifo != current_fifo:
                        console.print(f"[bold yellow]🔄 FIFO Switch: {current_fifo} → {new_fifo}[/bold yellow]")
                        current_fifo = new_fifo
                    last_fifo_check = now
                
                # Create FIFO if needed
                if not os.path.exists(current_fifo):
                    os.mkfifo(current_fifo)
                
                # Stats print every 30 seconds
                if now - last_stats_print > 30:
                    console.print(Panel(
                        f"Processed: {self.stats['processed']:,} | Blocked: {self.stats['blocked']:,} | "
                        f"Zero-day: {self.stats['zero_day']} | Latency: {self.stats['avg_latency_ms']:.1f}ms | "
                        f"Threshold: {self.dynamic_threshold:.4f}",
                        title="📊 [bold cyan]IDS STATS[/bold cyan]"
                    ))
                    last_stats_print = now
                
                # Read and process flows
                with open(current_fifo, 'r') as fifo:
                    for line in fifo:
                        data = json.loads(line)
                        src_ip = data.get("src_ip") or data.get("ip")
                        features = data.get("features")
                        
                        if not src_ip or not features:
                            continue
                        
                        # Whitelist check
                        if src_ip in SDNConfigV2.WHITELIST or src_ip.startswith(SDNConfigV2.INFRA_PREFIX):
                            continue
                        
                        # Cooldown check
                        now_check = time.time()
                        if src_ip in self.stats["blocked_ips"]:
                            if now_check - self.stats["blocked_ips"][src_ip] < SDNConfigV2.COOLDOWN_TIME:
                                continue
                            else:
                                del self.stats["blocked_ips"][src_ip]
                                self.stats["blocked"] = max(0, self.stats["blocked"] - 1)
                        
                        # Buffer management
                        with self.lock:
                            if len(self.ip_buffers) > SDNConfigV2.MAX_CONCURRENT_IPS:
                                self.ip_buffers.clear()
                                logger.warning("[BUFFER] Cleared due to too many IPs (spoofing?)")
                            
                            if src_ip not in self.ip_buffers:
                                self.ip_buffers[src_ip] = {"data": [], "last": now}
                            
                            self.ip_buffers[src_ip]["data"].append(features)
                            self.ip_buffers[src_ip]["last"] = now
                            
                            # Process when we have 10 flows
                            if len(self.ip_buffers[src_ip]["data"]) == SEQ_LEN:
                                seq = np.array(self.ip_buffers[src_ip]["data"])
                                del self.ip_buffers[src_ip]
                                threading.Thread(
                                    target=self.process_sequence,
                                    args=(src_ip, seq),
                                    daemon=True
                                ).start()
            
            except Exception as e:
                logger.error(f"[ERROR] {e}", exc_info=True)
                time.sleep(1)

# =====================================================================
# MAIN ENTRY POINT
# =====================================================================

def main():
    """Main function"""
    logger.info("=" * 70)
    logger.info("🚀 IDS Engine v2.1 - AI DDoS Detection + SDN Mitigation")
    logger.info("=" * 70)
    
    # Validate config
    SDNConfigV2.validate()
    
    # Initialize and run
    try:
        engine = IDSEngineV2()
        engine.run()
    except KeyboardInterrupt:
        logger.info("[EXIT] Interrupted by user")
    except Exception as e:
        logger.critical(f"[FATAL] {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
