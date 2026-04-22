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
    CORE_SWITCH_ID = os.environ.get("CORE_SWITCH_ID", "of:0000000000000006")
    HONEYPOT_PORT = os.environ.get("HONEYPOT_PORT", "2")
    
    # FIFO Paths (Dual mode)
    FIFO_PATH_NORMAL = os.environ.get("FIFO_NORMAL", "zeek_stream.json")
    FIFO_PATH_SLOWLORIS = os.environ.get("FIFO_SLOWLORIS", "zeek_stream_slowloris.json")
    FIFO_MARKER_NORMAL = ".marker_normal"
    FIFO_MARKER_SLOWLORIS = ".marker_slowloris"
    
    # Checkpoint
    CHECKPOINT_FILE = os.environ.get("CHECKPOINT_FILE", "ai/threshold_state.json")
    
    # Whitelist (INFRA_SUBNET - never block)
    WHITELIST = [
        "10.0.0.10", "10.0.0.11", "10.0.0.20",
        "10.0.0.100", "10.0.0.101", "10.0.0.102"
    ]
    INFRA_PREFIX = "10.0.0."
    
    # AI Logic
    EMA_ALPHA = float(os.environ.get("EMA_ALPHA", "0.05"))
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
            "timeout": 0,             # Changed to 0: AI Engine will manually delete or rely on ONOS idle-timeout
            "isPermanent": True,      # AI Engine v2 handles lifecycle
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
        
        # Buffers
        self.ip_buffers = {}
        self.blocked_ips = {}
        self.mse_history = []
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "processed": 0,
            "blocked": 0,
            "zero_day": 0,
            "avg_latency_ms": 0.0
        }
        
        logger.info(f"[IDS] Engine ready on device: {self.pipeline['device']}")
        logger.info(f"[IDS] Base threshold: {self.base_threshold:.4f}")
    
    def dynamic_threshold_update(self, mse_score):
        """Update threshold adaptively using EMA"""
        with self.lock:
            self.mse_history.append(mse_score)
            if len(self.mse_history) > 100:
                self.mse_history.pop(0)
            
            recent_mse = np.array(self.mse_history)
            mean_mse = np.mean(recent_mse)
            std_mse = np.std(recent_mse)
            
            k_factor = 1.5
            new_threshold = mean_mse + (k_factor * std_mse)
            
            self.dynamic_threshold = (
                SDNConfigV2.EMA_ALPHA * new_threshold +
                (1 - SDNConfigV2.EMA_ALPHA) * self.dynamic_threshold
            )
            
            # Clip to reasonable bounds
            self.dynamic_threshold = np.clip(
                self.dynamic_threshold,
                self.base_threshold * 0.5,
                self.base_threshold * 2.0
            )
            
            if abs(self.dynamic_threshold - self.base_threshold) / self.base_threshold > 0.05:
                pct_change = ((self.dynamic_threshold - self.base_threshold) / self.base_threshold) * 100
                logger.info(f"[ADAPT] Threshold: {self.base_threshold:.4f} → {self.dynamic_threshold:.4f} ({pct_change:+.1f}%)")
    
    def execute_mitigation(self, src_ip, attack_name, confidence, is_zero_day=False):
        """Execute SDN mitigation action"""
        
        if is_zero_day:
            action = "HONEYPOT (suspected zero-day)"
            treatment = "HONEYPOT"
            color = "bold magenta"
        elif confidence > 90.0:
            action = "DROP (high confidence)"
            treatment = "DROP"
            color = "bold red"
        else:
            action = "RATE_LIMIT (medium confidence)"
            treatment = "RATE_LIMIT"
            color = "bold yellow"
        
        SDNControllerV2.push_flow_rule(src_ip, treatment)
        
        # Alert panel
        msg = f"[bold]IP:[/bold] {src_ip}\n"
        msg += f"[bold]Type:[/bold] {attack_name}\n"
        msg += f"[bold]Confidence:[/bold] {confidence:.1f}%\n"
        msg += f"[bold]Action:[/bold] [{color}]{action}[/{color}]"
        
        console.print(Panel(msg, title="🚨 [bold red]IDS ALERT[/bold red]", expand=False))
    
    # 1. Warm-up: Bỏ qua 20 flows đầu tiên của mỗi IP để hệ thống ổn định
    # 2. Xử lý IP_Buffers để tránh khởi động dồn dập
    
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
                logger.debug(f"[WARMUP] Skipping sequence for {src_ip} (Attempt {self.ip_warmup_count[src_ip]}/2)")
                return
        
        # Feature engineering: 13 → 26 (add differential)
        diff = np.zeros_like(sequence)  # [SEQ_LEN, 13]
        diff[1:, :] = sequence[1:, :] - sequence[:-1, :]
        
        # Combine original + differential
        seq_combined = np.concatenate([sequence, diff], axis=-1)  # [SEQ_LEN, 26]
        
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
            mse = torch.mean((tensor_flat - recon_flat) ** 2).item()
            
            # Classifier: attack type
            logits, temporal_attn, spatial_weights = self.pipeline["cls_model"](tensor)
            probs = torch.softmax(logits, dim=1)
            pred_idx = torch.argmax(probs, dim=1).item()
            confidence = probs[0][pred_idx].item() * 100
        
        latency_ms = (time.time() - start_time) * 1000
        self.stats["avg_latency_ms"] = (self.stats["avg_latency_ms"] * 0.9) + (latency_ms * 0.1)
        
        # Decision logic (Cơ chế 2 Khiên & Phủ quyết AI Thuần AI)
        is_attack = False
        is_zero_day = False
        
        # KHIÊN 1: Autoencoder phát hiện bất thường (MSE)
        is_anomaly = (mse > self.dynamic_threshold)
        
        # KHIÊN 2: Classifier phân loại (Confidence)
        # Lấy xác suất của lớp Normal (index 0)
        normal_prob = probs[0][0].item() * 100
        
        if is_anomaly:
            # Nếu có bất thường, kiểm tra Classifier
            if pred_idx != 0 and confidence > 95.0:
                # CƠ CHẾ PHỦ QUYẾT: Nếu nhãn Normal vẫn có xác suất đáng kể (> 5%), phủ quyết lệnh chặn
                if normal_prob > 5.0:
                    logger.info(f"[VETO] AI Phủ quyết: {LABEL_NAMES[pred_idx]} bị từ chối vì Normal Prob còn cao ({normal_prob:.1f}%)")
                    is_attack = False
                else:
                    is_attack = True
            elif pred_idx == 0:
                # MSE cao nhưng nhãn là Normal -> Zero-day
                is_attack = True
                is_zero_day = True
        else:
            # Kể cả MSE thấp, nếu Classifier cực kỳ chắc chắn là tấn công (> 99%) 
            # thì vẫn có thể là tấn công lẩn trốn (Evasive Attack)
            if pred_idx != 0 and confidence > 99.0:
                is_attack = True
                logger.warning(f"[EVASIVE] Phát hiện tấn công lẩn trốn: {LABEL_NAMES[pred_idx]} (MSE thấp nhưng Confidence cực cao)")
        
        if is_attack:
            attack_name = LABEL_NAMES[pred_idx] if not is_zero_day else "ZERO-DAY / VARIANT"
            self.execute_mitigation(src_ip, attack_name, confidence, is_zero_day)
            
            # XAI explanation
            try:
                explanation = self.explainer.explain_attack(
                    tensor, temporal_attn, spatial_weights, pred_idx
                )
                console.print(Panel(
                    explanation.get("explanation_text", ""),
                    title="📋 [bold cyan]XAI EXPLANATION[/bold cyan]",
                    expand=False
                ))
            except Exception as e:
                logger.debug(f"[XAI] Explanation failed: {e}")
            
            self.blocked_ips[src_ip] = time.time()
            self.stats["blocked"] += 1
            if is_zero_day:
                self.stats["zero_day"] += 1
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
        
        while True:
            try:
                now = time.time()
                
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
                        now = time.time()
                        if src_ip in self.blocked_ips:
                            if now - self.blocked_ips[src_ip] < SDNConfigV2.COOLDOWN_TIME:
                                continue
                            else:
                                del self.blocked_ips[src_ip]
                        
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
