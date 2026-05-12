# Tên file: config_v2.py - Phiên bản nâng cấp với 26 đặc trưng
import torch
import torch.nn as nn
import os
import joblib
import numpy as np

# =====================================================================
# 1. THÔNG SỐ TOÀN CỤC & ĐỊNH DANH MẠNG L3 (NÂNG CẤP)
# =====================================================================
NUM_FEATURES = 13              # 13 trường dữ liệu gốc (Bao gồm cả Src và Dst Port Entropy)
NUM_FEATURES_DIFF = 13         # 13 đặc trưng biến thiên
NUM_FEATURES_TOTAL = 26        # Tổng cộng: 13 + 13 = 26 đặc trưng

NUM_CLASSES = 5                # 0: Benign, 1: UDP, 2: SYN, 3: HTTP, 4: Slowloris
SEQ_LEN = 10                   # Cửa sổ trượt (10 luồng/chuỗi)

# ĐỊNH NGHĨA DẢI IP THEO KIẾN TRÚC L3 (system.py)
NETWORK_L3 = {
    "INFRA_SUBNET": "10.0.0.",   # Servers, Proxy, DB, DNS
    "BOTNET_SUBNET": "10.0.1.",  # Botnet nodes
    "CLIENT_SUBNET": "10.0.2.",  # Real users
    "PROXY_IP": "10.0.0.10",     # Nginx Proxy (Vị trí kết thúc Chặng 1)
    "WEB_SERVER_IP": "10.0.0.11" # Backend Server (Vị trí Chặng 2)
}

# ONOS & OVS Configuration
ONOS_CONFIG = {
    "controller_ip": "172.17.0.2",
    "controller_port": 6653,
    "rest_port": 8181,
    "rest_user": "onos",
    "rest_password": "rocks"
}

# Switch Configuration cho DROP actions
SWITCH_CONFIG = {
    "ingress_switch": "of:0000000000000001",  # Core Switch S1 - Chặn tại cửa ngõ trung tâm
    "secondary_switch": "of:0000000000000006", # S6 - Chặn dự phòng
    "default_drop_priority": 40000,           # Ưu tiên cực cao
    "timeout_sec": 0                          # Permanent (0) - AI Engine sẽ quản lý vòng đời
}

LABEL_NAMES = {
    0: "BENIGN (An toàn)", 
    1: "UDP FLOOD", 
    2: "TCP SYN FLOOD", 
    3: "HTTP GET/POST FLOOD", 
    4: "SLOWLORIS"
}

# Danh sách đặc trưng GỐC (13 trường)
FEATURE_NAMES_ORIGINAL = [
    "Src_Port_Entropy", "Dst_Port_Entropy",
    "Protocol", "Duration_Sec", 
    "Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets", 
    "Conn_State", "L7_App_Protocol", "Packet_Rate", "Byte_Rate", "Anomaly_Score"
]

# Danh sách đặc trưng BIẾN THIÊN (Differential)
FEATURE_NAMES_DIFFERENTIAL = [
    "d_Src_Port_Entropy", "d_Dst_Port_Entropy",
    "d_Protocol", "d_Duration_Sec", 
    "d_Src_Bytes", "d_Dst_Bytes", "d_Src_Packets", "d_Dst_Packets", 
    "d_Conn_State", "d_L7_App_Protocol", "d_Packet_Rate", "d_Byte_Rate", "d_Anomaly_Score"
]

# Danh sách ĐẦY ĐỦ (26 trường)
FEATURE_NAMES = FEATURE_NAMES_ORIGINAL + FEATURE_NAMES_DIFFERENTIAL

# NFStream / BatPack Configuration (Tối ưu cho Real-time)
class BatPackConfig:
    # Nới lỏng thời gian nhàn rỗi để tránh xẻ nhỏ luồng
    # Giúp AI nhìn thấy toàn cảnh luồng thay vì các mảnh vụn (giảm False Positive)
    IDLE_TIMEOUT = 2.0        # Giây
    ACTIVE_TIMEOUT = 10.0      # Giây
    
    # Các cổng hệ thống cần loại bỏ để tránh làm nhiễu AI
    RESTRICTED_PORTS = [22, 6633, 6653, 8181] 
    
    # Subnet definitions (for monitoring)
    CLIENT_SUBNET = "10.0.2.0/24"
    BOTNET_SUBNET = "10.0.1.0/24"
class AIModelManager:
    """Hỗ trợ nạp và quản lý các phiên bản mô hình khác nhau"""
    @staticmethod
    def load_full_pipeline(base_path="ai/"):
        import gc
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Nếu base_path rỗng hoặc là relative path, dùng đường dẫn tuyệt đối
        if not base_path or base_path == "ai/":
            base_path = os.path.dirname(os.path.abspath(__file__))
        
        try:
            # Clear cache to avoid zip container confusion
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            scaler = joblib.load(os.path.join(base_path, 'sdn_scaler.pkl'))
            
            # Autoencoder
            ae = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN).to(device)
            ae_path = os.path.join(base_path, 'sdn_autoencoder_contrastive.pth')
            
            # Force load to CPU first to isolate from GPU/Zip conflicts
            ae_state = torch.load(ae_path, map_location='cpu')
            ae.load_state_dict(ae_state)
            ae.eval()
            del ae_state
            
            # Classifier
            cls = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL).to(device)
            cls_path = os.path.join(base_path, 'sdn_model_parallel_fusion.pth')
            
            cls_state = torch.load(cls_path, map_location='cpu')
            cls.load_state_dict(cls_state)
            cls.eval()
            del cls_state
            
            # Final sync to device
            ae.to(device)
            cls.to(device)
            gc.collect()
            
            # XAI Explainer
            xai = SDN_XAI_Explainer_Advanced(feature_names=FEATURE_NAMES)
            
            threshold = joblib.load(os.path.join(base_path, 'ae_threshold.pkl'))
            
            return {
                "scaler": scaler,
                "ae_model": ae,
                "cls_model": cls,
                "xai_engine": xai,
                "threshold": threshold,
                "device": device
            }
        except Exception as e:
            print(f"[!] Lỗi nạp Pipeline AI: {e}")
            return None

# =====================================================================
# 3. KIẾN TRÚC MẠNG NƠ-RON (NÂNG CẤP)
# =====================================================================

# ===== 3.1 ATTENTION LAYER (Cơ bản cho Temporal Focus) =====
class AttentionLayer(nn.Module):
    """Temporal Attention - Tìm ra flow (bước thời gian) quan trọng nhất"""
    def __init__(self, hidden_size):
        super(AttentionLayer, self).__init__()
        self.attention = nn.Linear(hidden_size, 1, bias=False)

    def forward(self, gru_outputs):
        # gru_outputs shape: (Batch, Seq_Len, Hidden_Size)
        # 1. Chấm điểm từng luồng mạng trong chuỗi (luồng nào khả nghi điểm càng cao)
        scores = self.attention(gru_outputs).squeeze(2) 
        
        # 2. Dùng Softmax để quy đổi điểm thành phần trăm (Tổng = 100%)
        alphas = torch.softmax(scores, dim=-1) 
        
        # 3. Nhân trọng số phần trăm này ngược lại vào các luồng mạng (Tạo ra Context Vector)
        context = torch.bmm(alphas.unsqueeze(1), gru_outputs).squeeze(1)
        
        # Trả về Context (để phân loại) và Alphas (để giải thích)
        return context, alphas


# ===== 3.2 SPATIAL ATTENTION (Đặc trưng nào quan trọng) =====
class SpatialAttention(nn.Module):
    """Spatial Attention - Ưu tiên các đặc trưng quan trọng (Packet_Rate, Byte_Rate, ...)"""
    def __init__(self, num_features):
        super(SpatialAttention, self).__init__()
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


# ===== 3.3 MULTI-SCALE RESIDUAL BLOCK (CNN với kernel khác nhau) =====
class MultiScaleResidualBlock(nn.Module):
    """Residual CNN Đa tầng (Multi-Scale) với Kernel size khác nhau"""
    def __init__(self, in_channels, out_channels):
        super(MultiScaleResidualBlock, self).__init__()
        # Nhánh 1: Kernel 3 (Cục bộ - Local pattern)
        self.branch3 = nn.Sequential(
            nn.Conv1d(in_channels, out_channels // 2, kernel_size=3, padding=1),
            nn.BatchNorm1d(out_channels // 2),
            nn.ReLU()
        )
        # Nhánh 2: Kernel 5 (Ngữ cảnh rộng - Contextual pattern)
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


# ===== 3.4 CONTRASTIVE AUTOENCODER (Triplet Loss) =====
class Anomaly_Autoencoder_Contrastive(nn.Module):
    """
    Autoencoder với Contrastive Learning:
    - Normal flows: Reconstruct well (MSE thấp)
    - Attack flows: Reconstruct poorly (MSE cao) -> Anomaly Score cao
    """
    def __init__(self, input_dim=NUM_FEATURES_TOTAL * SEQ_LEN):
        super(Anomaly_Autoencoder_Contrastive, self).__init__()
        
        # Encoder: Nén dữ liệu vào latent space [NÂNG CẤP] Wider & Deeper cho Colab GPU
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 512),       # Tăng từ 256 -> 512
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.25),                # Tăng dropout chút để cân bằng capacity
            nn.Linear(512, 256),             # Tăng từ 256 -> 512, 128 -> 256
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.25),
            nn.Linear(256, 128),             # Tăng 128 -> 256, 64 -> 128
            nn.ReLU(),
            nn.Linear(128, 64)               # Latent dimension tăng 32 -> 64
        )
        
        # Decoder: Giải nén từ latent space [NÂNG CẤP] Match với latent 64
        self.decoder = nn.Sequential(
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Linear(256, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.2),  # Tăng từ 0.1 lên 0.2
            nn.Linear(512, input_dim)
        )
        
        self.input_dim = input_dim

    def forward(self, x):
        batch_size = x.size(0)
        # x: [Batch, Seq, Features]
        input_feat_dim = x.size(2)
        x_flat = x.view(batch_size, -1)
        
        # Latent representation
        latent = self.encoder(x_flat)
        
        # Reconstruction
        reconstructed = self.decoder(latent)
        
        return reconstructed.view(batch_size, SEQ_LEN, input_feat_dim), latent

    def get_reconstruction_error(self, x):
        """Tính MSE giữa dữ liệu gốc và dữ liệu tái tạo"""
        batch_size = x.size(0)
        x_flat = x.view(batch_size, -1)
        recon, _ = self.forward(x)
        recon_flat = recon.view(batch_size, -1)
        error = torch.mean((x_flat - recon_flat) ** 2, dim=1)
        return error


# ===== 3.5 PARALLEL FUSION: CNN + GRU (Song song, không tuần tự) =====
class DDos_ParallelFusion_CNN_GRU_Attention(nn.Module):
    """
    Kiến trúc Parallel Fusion nâng cấp:
    - Nhánh CNN: Bắt đặc trưng không gian (spatial patterns) từ các flow
    - Nhánh GRU: Bắt đặc trưng thời gian (temporal patterns) giữa các flows
    - Fusion: Concatenate 2 nhánh, áp dụng Attention, phân loại
    """
    def __init__(self, input_dim=NUM_FEATURES_TOTAL):
        super(DDos_ParallelFusion_CNN_GRU_Attention, self).__init__()
        self.input_dim = input_dim
        
        # ===== NHÁNH 1: SPATIAL ATTENTION & CNN (Bắt điểm bất thường không gian) =====
        self.spatial_attn = SpatialAttention(input_dim)
        
        # Multi-Scale CNN (2 residual blocks)
        self.res_block1 = MultiScaleResidualBlock(input_dim, 64)
        self.res_block2 = MultiScaleResidualBlock(64, 128)
        self.dropout_cnn = nn.Dropout(0.2)
        
        # Pooling sau CNN để giảm chiều
        self.global_pool = nn.AdaptiveMaxPool1d(1)
        
        # ===== NHÁNH 2: BI-GRU (Bắt hành vi thời gian 2 chiều) =====
        self.gru = nn.GRU(
            input_size=input_dim,  
            hidden_size=128, 
            num_layers=2, 
            batch_first=True, 
            dropout=0.4,       # Tăng từ 0.3 lên 0.4 để ép mô hình học đa dạng đặc trưng
            bidirectional=True
        )
        
        # ===== TEMPORAL ATTENTION =====
        self.temporal_attn = AttentionLayer(hidden_size=256)  # 128 * 2 vì Bi-directional
        
        # ===== FUSION & CLASSIFIER =====
        # Kích thước input cho FC: 
        # - Từ CNN: 128 (sau pooling)
        # - Từ GRU + Attention: 256 (Bi-GRU output)
        # - Tổng: 128 + 256 = 384
        
        self.fc_fusion = nn.Sequential(
            nn.Linear(128 + 256, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.6),  # Tăng từ 0.5 lên 0.6 để ngăn "học vẹt" (Overfitting)
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.5),  # Tăng từ 0.4 lên 0.5
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, NUM_CLASSES)
        )

    def forward(self, x):
        """
        x: [Batch, Seq, Features] - 26 đặc trưng (13 gốc + 13 differential)
        """
        batch_size = x.size(0)
        
        # ===== NHÁNH CNN: Spatial Pattern Extraction =====
        x_spatial, spatial_weights = self.spatial_attn(x)  # [B, S, F]
        
        # CNN cần input: [B, F, S] (features on channel axis)
        x_cnn = x_spatial.permute(0, 2, 1)  # [B, F, S]
        x_cnn = self.res_block1(x_cnn)
        x_cnn = self.res_block2(x_cnn)      # [B, 128, S]
        x_cnn = self.dropout_cnn(x_cnn)
        
        # Global max pooling: [B, 128, S] -> [B, 128, 1] -> [B, 128]
        x_cnn_pool = self.global_pool(x_cnn).squeeze(-1)
        
        # ===== NHÁNH GRU: Temporal Pattern Extraction (PARALLEL, không Sequential) =====
        # CRITICAL FIX: GRU phải lấy spatial input gốc [B, S, F], KHÔNG phải CNN output
        # Để đảm bảo PARALLEL fusion (CNN xử lý spatial, GRU xử lý temporal độc lập)
        # Trước: x_gru_input = x_cnn.permute(0, 2, 1) → Sequential (GRU lấy CNN output)
        # Sau: x_gru_input = x_spatial → Parallel (GRU lấy spatial attention input)
        x_gru_input = x_spatial  # [B, S, F] - Use spatial-attention output directly
        gru_out, _ = self.gru(x_gru_input)     # [B, S, 256] (bidirectional)
        
        # Temporal Attention: [B, S, 256] -> [B, 256], weights [B, S]
        context_gru, temporal_weights = self.temporal_attn(gru_out)
        
        # ===== FUSION: Ghép 2 nhánh =====
        fused = torch.cat([x_cnn_pool, context_gru], dim=1)  # [B, 128+256=384]
        
        # ===== CLASSIFICATION =====
        logits = self.fc_fusion(fused)  # [B, 5]
        
        return logits, temporal_weights, spatial_weights


# =====================================================================
# 4. EXPLAINABLE AI (XAI) ENGINE - NÂNG CẤP
# =====================================================================
class SDN_XAI_Explainer_Advanced:
    """
    XAI Engine nâng cấp:
    - Giải thích dựa vào Spatial Attention (đặc trưng nào quan trọng)
    - Giải thích dựa vào Temporal Attention (flow nào bất thường)
    - Phân tích Differential Features để phát hiện sự biến thiên bất thường
    """
    def __init__(self, feature_names=FEATURE_NAMES):
        self.feature_names = feature_names
        self.original_features = FEATURE_NAMES_ORIGINAL
        self.differential_features = FEATURE_NAMES_DIFFERENTIAL

    def explain_attack(self, input_tensor, temporal_weights, spatial_weights, predicted_label):
        """
        Giải thích chi tiết vì sao AI phát hiện tấn công
        
        input_tensor: [1, Seq_Len, Num_Features] - 26 đặc trưng
        temporal_weights: [1, Seq_Len] - Trọng số thời gian
        spatial_weights: [1, Seq_Len, Num_Features] - Trọng số không gian
        predicted_label: int - 1-4 (tấn công) hoặc 0 (bình thường)
        """
        result = {
            "prediction": predicted_label,
            "label_name": LABEL_NAMES.get(predicted_label, "Unknown"),
            "confidence": 0,
            "explanations": []
        }
        
        if predicted_label == 0:
            result["explanation_text"] = "Luồng mạng bình thường, không phát hiện tấn công."
            return result
        
        # 1. Tìm flow (bước thời gian) có trọng số attention cao nhất
        temporal_weights_np = temporal_weights[0].cpu().detach().numpy()
        max_step_idx = np.argmax(temporal_weights_np)
        max_temporal_importance = temporal_weights_np[max_step_idx] * 100
        
        # 2. Lấy dữ liệu của flow đó
        suspicious_flow = input_tensor[0, max_step_idx].cpu().detach().numpy()
        spatial_weights_flow = spatial_weights[0, max_step_idx].cpu().detach().numpy()
        
        # 3. Tìm top 5 đặc trưng có trọng số spatial cao nhất
        top_feature_indices = np.argsort(np.abs(spatial_weights_flow))[-5:][::-1]
        
        top_features_explanation = []
        for rank, idx in enumerate(top_feature_indices, 1):
            feature_name = self.feature_names[idx]
            feature_value = suspicious_flow[idx]
            spatial_score = spatial_weights_flow[idx]
            
            # Phân loại đặc trưng (gốc vs differential)
            if idx < NUM_FEATURES:
                feature_type = "Original"
                original_name = self.original_features[idx]
            else:
                feature_type = "Differential"
                original_name = self.differential_features[idx - NUM_FEATURES]
            
            # Phân tích ý nghĩa
            if feature_type == "Differential":
                meaning = f"Sự thay đổi trong {original_name} từ flow trước rất bất thường"
            else:
                meaning = f"{original_name} có giá trị bất thường"
            
            top_features_explanation.append({
                "rank": rank,
                "feature": feature_name,
                "original_feature": original_name,
                "type": feature_type,
                "value": float(feature_value),
                "spatial_weight": float(spatial_score),
                "meaning": meaning
            })
        
        result["temporal_analysis"] = {
            "suspicious_flow_index": max_step_idx,
            "temporal_importance": float(max_temporal_importance),
            "reason": f"Flow #{max_step_idx} có hành vi bất thường nhất trong chuỗi"
        }
        
        result["spatial_analysis"] = {
            "top_features": top_features_explanation,
            "reason": "Những đặc trưng này có trọng số cao nhất theo Spatial Attention"
        }
        
        result["explanation_text"] = f"""
        🚨 PHÁT HIỆN {result['label_name']} 🚨
        
        ⏱️  PHÂN TÍCH THỜI GIAN:
        - Flow bất thường nhất: #{max_step_idx} (Tầm quan trọng: {max_temporal_importance:.1f}%)
        
        📊 PHÂN TÍCH ĐẶC TRƯNG (Top 3):
        """
        
        for exp in top_features_explanation[:3]:
            result["explanation_text"] += f"\n  {exp['rank']}. {exp['feature']} ({exp['type']}): {exp['meaning']}"
        
        return result

    def explain_autoencoder_anomaly(self, reconstruction_error, threshold):
        """Giải thích tại sao Autoencoder coi đây là anomaly"""
        is_anomaly = reconstruction_error > threshold
        
        return {
            "is_anomaly": is_anomaly,
            "reconstruction_error": float(reconstruction_error),
            "threshold": float(threshold),
            "error_ratio": float(reconstruction_error / max(threshold, 1e-6)) if threshold is not None else 0,
            "explanation": "Sai số tái tạo cao -> Normal data không thể tái tạo được -> Đây là Attack" if is_anomaly else "Sai số tái tạo bình thường -> Đây là Normal traffic"
        }
