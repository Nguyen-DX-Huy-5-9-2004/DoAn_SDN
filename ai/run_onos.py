# Tên file: run_onos.py
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
try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Import từ config_v2 (nâng cấp mới)
from config_v2 import (
    AIModelManager, SDN_XAI_Explainer_Advanced, SEQ_LEN, LABEL_NAMES, 
    FEATURE_NAMES, NUM_FEATURES_TOTAL, NUM_CLASSES
)

warnings.filterwarnings("ignore")
console = Console()

# =====================================================================
# LOGGING SETUP (Production - Task 6)
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
# 1. CẤU HÌNH HỆ THỐNG L3-AWARE
# =====================================================================
class SDNConfig:
    ONOS_URL = os.environ.get("ONOS_URL", "http://127.0.0.1:8181/onos/v1")
    ONOS_USER = os.environ.get("ONOS_USER", "onos")
    ONOS_PASS = os.environ.get("ONOS_PASS", "rocks")
    AUTH = (ONOS_USER, ONOS_PASS)
    CORE_SWITCH_ID = os.environ.get("CORE_SWITCH_ID", "of:0000000000000001")
    HONEYPOT_PORT = os.environ.get("HONEYPOT_PORT", "2")
    
    # MODEL PATH SUPPORT (Task 7)
    MODEL_BASE_PATH = os.environ.get("AI_MODEL_PATH", "ai/")
    
    # DUAL FIFO SUPPORT (Normal + Slowloris phases)
    FIFO_PATH_NORMAL = os.environ.get("FIFO_NORMAL", "zeek_stream.json")
    FIFO_PATH_SLOWLORIS = os.environ.get("FIFO_SLOWLORIS", "zeek_stream_slowloris.json")
    FIFO_MARKER_NORMAL = ".marker_normal"
    FIFO_MARKER_SLOWLORIS = ".marker_slowloris"
    
    CHECKPOINT_FILE = os.environ.get("CHECKPOINT_FILE", "ai/threshold_state.json")
    
    @staticmethod
    def detect_current_fifo():
        """Auto-detect which FIFO to read based on marker files"""
        if os.path.exists(SDNConfig.FIFO_MARKER_SLOWLORIS):
            return SDNConfig.FIFO_PATH_SLOWLORIS
        elif os.path.exists(SDNConfig.FIFO_MARKER_NORMAL):
            return SDNConfig.FIFO_PATH_NORMAL
        else:
            # Fallback: Try to detect based on which FIFO exists
            if os.path.exists(SDNConfig.FIFO_PATH_SLOWLORIS):
                return SDNConfig.FIFO_PATH_SLOWLORIS
            else:
                return SDNConfig.FIFO_PATH_NORMAL
    
    # WHITELIST: Loại bỏ hoàn toàn dải INFRA_SUBNET (10.0.0.x) khỏi việc chặn
    # để đảm bảo Proxy, Web, DB, DNS luôn thông suốt.
    WHITELIST = ["10.0.0.10", "10.0.0.11", "10.0.0.20", "10.0.0.100", "10.0.0.101", "10.0.0.102"]
    INFRA_PREFIX = "10.0.0."
    
    # AI Logic
    EMA_ALPHA = 0.05
    COOLDOWN_TIME = 300      
    BUFFER_TIMEOUT = 60      
    MAX_CONCURRENT_IPS = 1000 # Tăng lên cho môi trường L3 đông Client

# =====================================================================
# 2. MODULE ĐIỀU KHIỂN SDN (SDN CONTROLLER)
# =====================================================================
class SDNController:
    @staticmethod
    def push_flow_rule(src_ip, treatment):
        """Gửi lệnh xuống ONOS để thực thi chặn/điều hướng"""
        flow_rule = {
            "priority": 40000, 
            "timeout": SDNConfig.COOLDOWN_TIME,  # FIX: Sync timeout with cooldown
            "isPermanent": False,  # Changed from True to False
            "deviceId": SDNConfig.CORE_SWITCH_ID,
            "treatment": treatment,
            "selector": { 
                "criteria": [ 
                    {"type": "ETH_TYPE", "ethType": "0x0800"}, 
                    {"type": "IPV4_SRC", "ip": f"{src_ip}/32"} 
                ] 
            }
        }
        url = f"{SDNConfig.ONOS_URL}/flows/{SDNConfig.CORE_SWITCH_ID}"
        try:
            threading.Thread(target=lambda: requests.post(
                url, json=flow_rule, auth=SDNConfig.AUTH, timeout=3
            ), daemon=True).start()
            return True
        except Exception:
            return False

# =====================================================================
# 3. CỖ MÁY IDS (IDS ENGINE)
# =====================================================================
class IDSEngine:
    def __init__(self):
        logger.info("[IDS] Initializing IDS Engine with MODEL_PATH: %s", SDNConfig.MODEL_BASE_PATH)
        self.pipeline = AIModelManager.load_full_pipeline(SDNConfig.MODEL_BASE_PATH)  # Task 7: Use env variable
        if not self.pipeline:
            logger.critical("[IDS] Failed to load AI pipeline!")
            console.print("[bold red]❌ Không thể khởi động IDS Engine do lỗi Pipeline![/bold red]")
            exit(1)
            
        self.explainer = SDN_XAI_Explainer_Advanced(feature_names=FEATURE_NAMES)
        self.dynamic_threshold = self.pipeline["threshold"]
        self.base_threshold = self.pipeline["threshold"]
        logger.info("[IDS] Loaded models successfully. Base threshold: %.4f", self.base_threshold)
        logger.info("[IDS] Device: %s", self.pipeline.get('device', 'cpu'))
        
        # Buffers & Tracking
        self.ip_buffers = {}
        self.blocked_ips = {}
        self.last_log_time = {}
        self.lock = threading.Lock()
        
        # Stats for Monitor
        self.stats = {"processed": 0, "blocked": 0, "zero_day": 0, "avg_latency": 0}
        self.mse_history = []

    def _plot_attention_heatmap(self, src_ip, sequence, temporal_attn):
        if plt is None:
            return
        try:
            weights = temporal_attn[0].cpu().detach().numpy()
            durations = sequence[:, 3] if sequence.shape[1] > 3 else np.arange(sequence.shape[0])
            fig, ax = plt.subplots(2, 1, figsize=(8, 4), gridspec_kw={'height_ratios': [1, 3]})
            ax[0].plot(durations, marker='o', color='tab:blue')
            ax[0].set_title('Duration over sequence')
            ax[0].set_ylabel('Duration')
            ax[1].bar(range(len(weights)), weights, color='tab:red')
            ax[1].set_title('Temporal Attention Weights')
            ax[1].set_xlabel('Sequence step')
            fig.tight_layout()
            filename = f"ai/xai_attention_{src_ip.replace('.', '_')}_{int(time.time())}.png"
            plt.savefig(filename)
            plt.close(fig)
            console.print(f"[green]📌 XAI heatmap saved to {filename}[/green]")
        except Exception:
            pass

    def dynamic_threshold_update(self, mse):
        """✅ ENHANCEMENT: Adaptive threshold bằng rolling statistics."""
        with self.lock:
            self.mse_history.append(mse)
            if len(self.mse_history) > 100:
                self.mse_history.pop(0)
            recent_mse = np.array(self.mse_history)
            mean_mse = np.mean(recent_mse)
            std_mse = np.std(recent_mse)
            k_factor = 1.5
            new_threshold = mean_mse + (k_factor * std_mse)
            self.dynamic_threshold = (
                SDNConfig.EMA_ALPHA * new_threshold + 
                (1 - SDNConfig.EMA_ALPHA) * self.dynamic_threshold
            )
            self.dynamic_threshold = np.clip(
                self.dynamic_threshold,
                self.base_threshold * 0.5,
                self.base_threshold * 1.5
            )
            if abs(self.dynamic_threshold - self.base_threshold) / self.base_threshold > 0.01:
                change_pct = ((self.dynamic_threshold - self.base_threshold) / self.base_threshold) * 100
                console.print(
                    f"[yellow]⚙️ Dynamic Threshold Updated:[/yellow] {self.base_threshold:.4f} → {self.dynamic_threshold:.4f} ({change_pct:+.1f}%)"
                )

    def execute_mitigation(self, src_ip, attack_name, confidence, is_zero_day=False):
        treatment = {}
        if is_zero_day:
            action, color = "REDIRECT TO HONEYPOT", "bold magenta"
            treatment = { "instructions": [{"type": "OUTPUT", "port": SDNConfig.HONEYPOT_PORT}] }
            logger.warning("[MITIGATION] Zero-day attack from %s, redirecting to honeypot", src_ip)
        elif confidence > 90.0:
            action, color = "DROP (CHẶN HOÀN TOÀN)", "bold red"
            treatment = { "instructions": [{"type": "DROP"}] }
            logger.warning("[MITIGATION] High-confidence %s attack from %s (%.1f%%), dropping", attack_name, src_ip, confidence)
        else:
            action, color = "RATE LIMIT (ÉP BĂNG THÔNG)", "bold yellow"
            treatment = { "instructions": [{"type": "METER", "meterId": "1"}] }
            logger.warning("[MITIGATION] Medium-confidence %s attack from %s (%.1f%%), rate limiting", attack_name, src_ip, confidence)

        SDNController.push_flow_rule(src_ip, treatment)
        
        # Hiển thị Panel thông báo
        msg = f"[bold]IP:[/bold] {src_ip} | [bold]Loại:[/bold] {attack_name}\n"
        msg += f"[bold]Độ tin cậy:[/bold] {confidence:.2f}% | [{color}]=> {action}[/{color}]"
        console.print(Panel(msg, title="🚨 [bold red]IDS ALERT[/bold red]", expand=False))

    def process_sequence(self, src_ip, sequence):
        start_time = time.time()
        
        # ✅ FIX #1: CORRECT FEATURE ENGINEERING ORDER
        # Step 1: Calculate differential features from RAW data (13 features)
        diff = np.zeros_like(sequence)  # [SEQ_LEN, 13]
        diff[1:, :] = sequence[1:, :] - sequence[:-1, :]
        
        # Step 2: Combine original + differential (26 features total)
        seq_combined = np.concatenate([sequence, diff], axis=-1)  # [SEQ_LEN, 26]
        
        # Step 3: Scale entire 26 features together (matches training pipeline)
        seq_combined_reshaped = seq_combined.reshape(-1, NUM_FEATURES_TOTAL)
        seq_scaled = self.pipeline["scaler"].transform(seq_combined_reshaped)  # ✅ Now correct dimension!
        seq_scaled = seq_scaled.reshape(SEQ_LEN, NUM_FEATURES_TOTAL)  # [SEQ_LEN, 26]
        seq_with_diff = seq_scaled
        
        # Validation assertion
        assert seq_with_diff.shape == (SEQ_LEN, NUM_FEATURES_TOTAL), \
            f"Feature shape mismatch! Expected ({SEQ_LEN}, {NUM_FEATURES_TOTAL}), got {seq_with_diff.shape}"
        
        tensor = torch.FloatTensor(seq_with_diff).unsqueeze(0).to(self.pipeline["device"])  # [1, SEQ_LEN, 26]
        
        with torch.no_grad():
            # 1. Khiên 1: Autoencoder (trả về 2 giá trị: recon, latent)
            recon, latent = self.pipeline["ae_model"](tensor)
            recon_flat = recon.view(recon.size(0), -1)
            tensor_flat = tensor.view(tensor.size(0), -1)
            mse = torch.mean((tensor_flat - recon_flat)**2).item()
            
            # 2. Khiên 2: Classifier (trả về 3 giá trị: logits, temporal_weights, spatial_weights)
            logits, temporal_attn, spatial_weights = self.pipeline["cls_model"](tensor)
            probs = torch.softmax(logits, dim=1)
            pred_idx = torch.argmax(probs, dim=1).item()
            confidence = probs[0][pred_idx].item() * 100
            
        latency = (time.time() - start_time) * 1000
        self.stats["avg_latency"] = (self.stats["avg_latency"] * 0.9) + (latency * 0.1)
        
        # ✅ FIX #2: EXPLAINABLE AI INTEGRATION
        # PHÂN TÍCH BẰNG XAI EXPLAINER
        explanation = None
        if pred_idx > 0 or mse > self.dynamic_threshold:
            explanation = self.explainer.explain_attack(
                tensor, temporal_attn, spatial_weights, pred_idx
            )
        
        # LOGIC QUYẾT ĐỊNH
        is_attack = False
        is_zero_day = False
        
        if mse > self.dynamic_threshold:
            # Kiểm tra XAI để tránh False Positive
            top_feat = "Unknown"
            if explanation and "spatial_analysis" in explanation:
                top_feats = explanation["spatial_analysis"].get("top_features", [])
                if len(top_feats) > 0:
                    top_feat = top_feats[0].get("feature", "Unknown")
            
            # Whitelist các đặc trưng "hiền tính" (burst traffic tự nhiên)
            if pred_idx == 0 and confidence > 90.0 and top_feat in ["Dst_Bytes", "Src_Bytes", "Byte_Rate", "d_Dst_Bytes", "d_Src_Bytes", "d_Byte_Rate"]:
                # Phủ quyết: Đây là burst traffic bình thường, nới lỏng threshold
                with self.lock:
                    self.dynamic_threshold = min(self.base_threshold * 3, self.dynamic_threshold * 1.05)
            else:
                is_attack = True
                is_zero_day = (pred_idx == 0)
        elif pred_idx != 0 and confidence > 90.0:
            is_attack = True

        if is_attack:
            attack_name = LABEL_NAMES[pred_idx] if not is_zero_day else "ZERO-DAY / VARIANT"
            self.execute_mitigation(src_ip, attack_name, confidence, is_zero_day)
            
            # ✅ XAI OUTPUT: Hiển thị giải thích tấn công
            if explanation:
                self._plot_attention_heatmap(src_ip, sequence, temporal_attn)
                console.print(Panel(
                    explanation["explanation_text"],
                    title="📋 [bold cyan]XAI EXPLANATION[/bold cyan]",
                    expand=False
                ))
            
            self.blocked_ips[src_ip] = time.time()
            self.stats["blocked"] += 1
            if is_zero_day: self.stats["zero_day"] += 1
        else:
            # Cập nhật Adaptive Threshold cho dữ liệu sạch
            if pred_idx == 0:
                self.dynamic_threshold_update(mse)
        self.stats["processed"] += 1

    def run(self):
        logger.info("=" * 70)
        logger.info("[IDS] Starting IDS Engine on device: %s", self.pipeline['device'])
        logger.info("[IDS] Dual FIFO mode enabled: zeek_stream.json + zeek_stream_slowloris.json")
        logger.info("=" * 70)
        
        console.print(f"[bold green]🚀 IDS Engine đã sẵn sàng trên {self.pipeline['device']}[/bold green]")
        console.print("[bold cyan]📡 IDS hỗ trợ DUAL FIFO: zeek_stream.json (Normal/Attack) + zeek_stream_slowloris.json (Slowloris)[/bold cyan]")
        
        last_fifo_check = 0
        current_fifo = SDNConfig.FIFO_PATH_NORMAL
        
        while True:
            try:
                # Detect FIFO change every 1 second (in case phase switched)
                now = time.time()
                if now - last_fifo_check > 1.0:
                    new_fifo = SDNConfig.detect_current_fifo()
                    if new_fifo != current_fifo:
                        console.print(f"[bold yellow]🔄 PHASE SWITCH DETECTED: {current_fifo} → {new_fifo}[/bold yellow]")
                        current_fifo = new_fifo
                    last_fifo_check = now
                
                # Ensure FIFO exists
                if not os.path.exists(current_fifo):
                    os.mkfifo(current_fifo)

                with open(current_fifo, 'r') as fifo:
                    for line in fifo:
                        data = json.loads(line)
                        src_ip, feats = data.get("src_ip"), data.get("features")
                        if not src_ip: src_ip = data.get("ip") # Fallback
                        
                        # KIỂM TRA L3-AWARE: Bỏ qua traffic nội bộ 10.0.0.x
                        if not src_ip or src_ip in SDNConfig.WHITELIST or src_ip.startswith(SDNConfig.INFRA_PREFIX):
                            continue
                        
                        now = time.time()
                        # Chống chặn trùng lặp
                        if src_ip in self.blocked_ips:
                            if now - self.blocked_ips[src_ip] < SDNConfig.COOLDOWN_TIME: continue
                            else: del self.blocked_ips[src_ip]

                        with self.lock:
                            # Chống Spoofing
                            if len(self.ip_buffers) > SDNConfig.MAX_CONCURRENT_IPS:
                                self.ip_buffers.clear()
                                console.print("[bold red]⚠️ Cảnh báo Spoofing: Đã reset bộ đệm IP![/bold red]")
                            
                            if src_ip not in self.ip_buffers:
                                self.ip_buffers[src_ip] = {"data": [], "last": now}
                            
                            self.ip_buffers[src_ip]["data"].append(feats)
                            self.ip_buffers[src_ip]["last"] = now
                            
                            if len(self.ip_buffers[src_ip]["data"]) == SEQ_LEN:
                                seq = np.array(self.ip_buffers[src_ip]["data"])
                                del self.ip_buffers[src_ip]
                                threading.Thread(target=self.process_sequence, args=(src_ip, seq), daemon=True).start()
            except Exception as e:
                time.sleep(1)

if __name__ == "__main__":
    engine = IDSEngine()
    engine.run()
