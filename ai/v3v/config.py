# Tên file: config.py
import torch
import torch.nn as nn
import os
import joblib
import numpy as np

# =====================================================================
# 1. THÔNG SỐ TOÀN CỤC & ĐỊNH DANH MẠNG L3
# =====================================================================
NUM_FEATURES = 13    # 13 trường dữ liệu chuẩn xác từ batPack
NUM_CLASSES = 5      # 0: Benign, 1: UDP, 2: SYN, 3: HTTP, 4: Slowloris
SEQ_LEN = 10         # Cửa sổ trượt (10 luồng/chuỗi)

# ĐỊNH NGHĨA DẢI IP THEO KIẾN TRÚC L3 (system.py)
NETWORK_L3 = {
    "INFRA_SUBNET": "10.0.0.",      # Servers, Proxy, DB, DNS
    "BOTNET_SUBNET": "10.0.1.",     # Botnet nodes (h1-h20)
    "CLIENT_SUBNET": "10.0.2.",     # Real users (h60-h65)
    "PROXY_IP": "10.0.0.10",        # Nginx Proxy (PORT: 8000)
    "WEB_SERVER_IP": "10.0.0.11",   # Backend Server
    "SERVICE_HOSTS": {
        "h70": "10.0.0.100",  # Web datacenter service
        "h71": "10.0.0.101",  # DNS service
        "h72": "10.0.0.102",  # API service
    },
    "SECURITY_HOSTS": {
        "h80": "10.0.0.200",  # IDS
        "h81": "10.0.0.201",  # Honeypot
        "h82": "10.0.0.202",  # Monitor
    }
}

LABEL_NAMES = {
    0: "BENIGN (An toàn)", 
    1: "UDP FLOOD", 
    2: "TCP SYN FLOOD", 
    3: "HTTP GET/POST FLOOD", 
    4: "SLOWLORIS"
}

# =====================================================================
# 1.5 ATTACK DETECTION - Identify attacker hosts by phase
# =====================================================================
ATTACK_PHASES = {
    "PHASE_1_UDP": {
        "name": "UDP Flood Attack",
        "label": 1,
        "attacker_hosts": list(range(1, 5)),      # h1-h4
        "attack_type": "UDP Flood",
        "description": "High-volume UDP packets to port 8000"
    },
    "PHASE_2_SYN": {
        "name": "SYN Flood Attack", 
        "label": 2,
        "attacker_hosts": list(range(6, 11)),     # h6-h10
        "attack_type": "SYN Flood",
        "description": "TCP SYN packets with spoofed IPs"
    },
    "PHASE_3_HTTP": {
        "name": "HTTP Flood Attack",
        "label": 3,
        "attacker_hosts": list(range(11, 15)),    # h11-h14
        "attack_type": "HTTP Flood",
        "description": "High-volume HTTP GET/POST requests"
    },
    "PHASE_4_SLOWLORIS": {
        "name": "Slowloris Attack",
        "label": 4,
        "attacker_hosts": list(range(16, 21)),    # h16-h20
        "attack_type": "Slowloris",
        "description": "Slow HTTP requests with hanging connections"
    },
    "PHASE_0_NORMAL": {
        "name": "Normal Traffic",
        "label": 0,
        "attacker_hosts": list(range(60, 66)),    # h60-h65 (legitimate clients)
        "attack_type": "Normal",
        "description": "Legitimate user traffic"
    }
}

def get_attacker_ips(phase_name=None):
    """Get IPs of attacker hosts for a specific phase or all phases"""
    if phase_name and phase_name in ATTACK_PHASES:
        hosts = ATTACK_PHASES[phase_name]["attacker_hosts"]
    else:
        hosts = []
        for phase_info in ATTACK_PHASES.values():
            if phase_info["attack_type"] != "Normal":  # Exclude normal clients
                hosts.extend(phase_info["attacker_hosts"])
    
    return [f"10.0.1.{h}" for h in hosts]  # Convert to IPs (10.0.1.x subnet)

def classify_flow(src_ip, dst_ip):
    """Classify flow as attack/normal based on source IP"""
    # Normal clients: 10.0.2.x
    if src_ip.startswith("10.0.2."):
        return 0, "NORMAL"
    
    # Botnet/Attack: 10.0.1.x
    if src_ip.startswith("10.0.1."):
        src_host_num = int(src_ip.split(".")[-1])
        
        if 1 <= src_host_num <= 4:
            return 1, "UDP_FLOOD"
        elif 6 <= src_host_num <= 10:
            return 2, "SYN_FLOOD"
        elif 11 <= src_host_num <= 14:
            return 3, "HTTP_FLOOD"
        elif 16 <= src_host_num <= 20:
            return 4, "SLOWLORIS"
        else:
            return 0, "UNKNOWN_BOTNET"
    
    # Other sources
    return 0, "OTHER"

# ═══════════════════════════════════════════════════════════════════
# 3. CAPTURE INTERFACE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
# Optimal capture point: s6-eth1 (L3 backbone, preserves original IPs)
# Why s6-eth1 and NOT s6-eth5?
#   - s6-eth1: Backbone between s1 (CORE) and s6 (WEB SERVER SWITCH)
#             Captures BOTH client→web AND web→client flows
#             NO SNAT (Source NAT), original IPs preserved
#             Filter pass rate: 99.7% ✅
#   - s6-eth5: Docker bridge with SNAT (Source NAT)
#             Modifies response IPs, breaks filter logic
#             Filter pass rate: 16% ❌
CAPTURE_INTERFACE = {
    "preferred": "s6-eth1",        # L3 backbone - BEST
    "fallback": ["s6-eth4", "h82-eth1", "s6-eth2"],  # Alternatives
    "filter_logic": {
        "bidirectional": True,      # Capture REQUEST + RESPONSE
        "request": {                # 10.0.1/2.x → 10.0.0.10:8000
            "target_services": ["10.0.0.10", "10.0.0.11"],
            "target_ports": [80, 443, 8000]
        },
        "response": {               # 10.0.0.10:8000 → 10.0.1/2.x:random
            "source_services": ["10.0.0.10", "10.0.0.11"],
            "source_ports": [8000, 80, 443]
        }
    }
}

# Danh sách đặc trưng khớp 100% với batPack.py
FEATURE_NAMES = [
    "Src_Port", "Dst_Port", "Protocol", "Duration_Sec", 
    "Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets", 
    "Conn_State", "L7_App_Protocol", "Packet_Rate", "Byte_Rate", "Anomaly_Score"
]

# =====================================================================
# 2. QUẢN LÝ MÔ HÌNH (MODEL MANAGER)
# =====================================================================
class AIModelManager:
    """Hỗ trợ nạp và quản lý các phiên bản mô hình khác nhau"""
    @staticmethod
    def load_full_pipeline(base_path="ai/"):
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        try:
            scaler = joblib.load(os.path.join(base_path, 'sdn_scaler.pkl'))
            
            ae = Anomaly_Autoencoder(input_dim=NUM_FEATURES * 2).to(device)
            ae.load_state_dict(torch.load(os.path.join(base_path, 'sdn_autoencoder.pth'), map_location=device))
            ae.eval()
            
            cls = DDos_Residual_CNN_GRU_Attention(input_dim=NUM_FEATURES * 2).to(device)
            cls.load_state_dict(torch.load(os.path.join(base_path, 'sdn_model_cnn_gru_attn.pth'), map_location=device))
            cls.eval()
            
            threshold = joblib.load(os.path.join(base_path, 'ae_threshold.pkl'))
            
            return {
                "scaler": scaler,
                "ae_model": ae,
                "cls_model": cls,
                "threshold": threshold,
                "device": device
            }
        except Exception as e:
            print(f"[!] Lỗi nạp Pipeline AI: {e}")
            return None

# =====================================================================
# 3. KIẾN TRÚC MẠNG NƠ-RON
# =====================================================================

class Anomaly_Autoencoder(nn.Module):
    def __init__(self, input_dim=None):
        super(Anomaly_Autoencoder, self).__init__()
        # input_dim: (NUM_FEATURES * 2) * SEQ_LEN nếu dùng Differential Features
        if input_dim is None:
            input_dim = NUM_FEATURES * SEQ_LEN 
        else:
            input_dim = input_dim * SEQ_LEN
            
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32)
        )
        
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim)
        )

    def forward(self, x):
        batch_size = x.size(0)
        # x: [Batch, Seq, Features]
        input_feat_dim = x.size(2)
        x_flat = x.view(batch_size, -1)
        latent = self.encoder(x_flat)
        reconstructed = self.decoder(latent)
        return reconstructed.view(batch_size, SEQ_LEN, input_feat_dim)

class SpatialAttention(nn.Module):
    """Attention hai chiều (Spatial-Temporal) - Phần Spatial (Đặc trưng nào quan trọng)"""
    def __init__(self, num_features):
        super(SpatialAttention, self).__init__()
        # Ưu tiên các cột Packet_Rate, Byte_Rate, Protocol, Conn_State
        self.attn = nn.Sequential(
            nn.Linear(num_features, num_features // 2),
            nn.ReLU(),
            nn.Linear(num_features // 2, num_features),
            nn.Sigmoid()
        )

    def forward(self, x):
        # x: [Batch, Seq, Features]
        weights = self.attn(x)
        return x * weights, weights

class MultiScaleResidualBlock(nn.Module):
    """Residual CNN Đa tầng (Multi-Scale) với Kernel size khác nhau"""
    def __init__(self, in_channels, out_channels):
        super(MultiScaleResidualBlock, self).__init__()
        # Nhánh 1: Kernel 3 (Cục bộ)
        self.branch3 = nn.Sequential(
            nn.Conv1d(in_channels, out_channels // 2, kernel_size=3, padding=1),
            nn.BatchNorm1d(out_channels // 2),
            nn.ReLU()
        )
        # Nhánh 2: Kernel 5 (Ngữ cảnh rộng hơn)
        self.branch5 = nn.Sequential(
            nn.Conv1d(in_channels, out_channels // 2, kernel_size=5, padding=2),
            nn.BatchNorm1d(out_channels // 2),
            nn.ReLU()
        )
        
        self.fusion = nn.Conv1d(out_channels, out_channels, kernel_size=1)
        self.bn = nn.BatchNorm1d(out_channels)
        self.relu = nn.ReLU()
        
        self.shortcut = nn.Sequential()
        if in_channels != out_channels:
            self.shortcut = nn.Sequential(
                nn.Conv1d(in_channels, out_channels, kernel_size=1),
                nn.BatchNorm1d(out_channels)
            )

    def forward(self, x):
        residual = self.shortcut(x)
        out3 = self.branch3(x)
        out5 = self.branch5(x)
        out = torch.cat([out3, out5], dim=1)
        out = self.bn(self.fusion(out))
        out += residual
        return self.relu(out)

class DDos_Residual_CNN_GRU_Attention(nn.Module):
    def __init__(self, input_dim=NUM_FEATURES):
        super(DDos_Residual_CNN_GRU_Attention, self).__init__()
        self.input_dim = input_dim
        
        # 1. Spatial Attention (Feature-wise)
        self.spatial_attn = SpatialAttention(input_dim)
        
        # 2. Multi-Scale Residual CNN
        self.res_block1 = MultiScaleResidualBlock(input_dim, 64)
        self.res_block2 = MultiScaleResidualBlock(64, 128)
        
        self.dropout_cnn = nn.Dropout(0.2)
        
        # 3. Bi-GRU (Temporal Context)
        self.gru = nn.GRU(input_size=128, hidden_size=128, num_layers=2, 
                          batch_first=True, dropout=0.3, bidirectional=True)
        
        # 4. Temporal Attention
        self.temporal_attn = AttentionLayer(hidden_size=256)
        
        # 5. Classifier
        self.fc = nn.Sequential(
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, NUM_CLASSES)
        )

    def forward(self, x):
        # x: [Batch, Seq, Features]
        
        # Spatial Attention: Trích xuất đặc trưng biến thiên ngầm
        x_spatial, spatial_weights = self.spatial_attn(x)
        
        # CNN Input: [Batch, Features, Seq]
        x_cnn = x_spatial.permute(0, 2, 1)
        x_cnn = self.res_block1(x_cnn)
        x_cnn = self.res_block2(x_cnn)
        x_cnn = self.dropout_cnn(x_cnn)
        
        # GRU Input: [Batch, Seq, Hidden]
        x_gru = x_cnn.permute(0, 2, 1)
        gru_out, _ = self.gru(x_gru)
        
        # Temporal Attention: Tìm thời điểm quan trọng
        context, temporal_weights = self.temporal_attn(gru_out)
        
        out = self.fc(context)
        return out, temporal_weights, spatial_weights

# =====================================================================
# 4. EXPLAINABLE AI (XAI) ENGINE
# =====================================================================
class SDN_XAI_Explainer:
    def __init__(self, feature_names=FEATURE_NAMES):
        self.feature_names = feature_names

    def explain(self, input_tensor, attn_weights):
        """
        Phân tích trọng số Attention để tìm ra đặc trưng gây ra quyết định
        input_tensor: [1, Seq_Len, Num_Features]
        attn_weights: [1, Seq_Len]
        """
        # 1. Tìm flow (bước thời gian) có trọng số attention cao nhất
        max_step_idx = torch.argmax(attn_weights).item()
        importance = attn_weights[0, max_step_idx].item() * 100
        
        # 2. Lấy dữ liệu của flow đó (đã scale)
        suspicious_flow = input_tensor[0, max_step_idx].cpu().numpy()
        
        # 3. Tìm top 3 đặc trưng có giá trị tuyệt đối lớn nhất trong flow đó
        # (Đây là cách tiếp cận đơn giản nhưng hiệu quả cho real-time)
        top_feature_indices = np.argsort(np.abs(suspicious_flow))[-3:][::-1]
        
        explanations = []
        for idx in top_feature_indices:
            explanations.append({
                "feature": self.feature_names[idx],
                "score": suspicious_flow[idx],
                "rank": len(explanations) + 1
            })
            
        return {
            "top_flow_index": max_step_idx,
            "flow_importance": importance,
            "top_features": explanations
        }