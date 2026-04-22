# Tên file: config.py
import torch
import torch.nn as nn

# --- CẤU HÌNH THÔNG SỐ TOÀN CỤC ---
NUM_FEATURES = 20    # 20 trường dữ liệu đã thống nhất
NUM_CLASSES = 5      # 0: Benign, 1: UDP, 2: SYN, 3: HTTP, 4: Slowloris
SEQ_LEN = 10         # Cửa sổ trượt (10 luồng/chuỗi)

LABEL_NAMES = {
    0: "BENIGN (An toàn)", 
    1: "UDP FLOOD", 
    2: "TCP SYN FLOOD", 
    3: "HTTP GET/POST FLOOD", 
    4: "SLOWLORIS"
}

# XAI sẽ dùng danh sách này để in ra giải thích.
FEATURE_NAMES = [
    "Duration", "Protocol", "Flow_Bytes", "Flow_Packets", "Packet_Rate",
    "Byte_Rate", "Fwd_Packets", "Bwd_Packets", "Fwd_Bytes", "Bwd_Bytes",
    "Fwd_Pkt_Len_Max", "Bwd_Pkt_Len_Max", "Fwd_Pkt_Len_Mean", "Bwd_Pkt_Len_Mean",
    "SYN_Flag_Count", "ACK_Flag_Count", "FIN_Flag_Count", "RST_Flag_Count",
    "Active_Mean", "Idle_Mean"
]

# KIẾN TRÚC 1: MẠNG AUTOENCODER (BẮT ZERO-DAY ANOMALY)
class Anomaly_Autoencoder(nn.Module):
    def __init__(self):
        super(Anomaly_Autoencoder, self).__init__()
        input_dim = NUM_FEATURES * SEQ_LEN 
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
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
        x_flat = x.view(batch_size, -1)
        latent = self.encoder(x_flat)
        reconstructed = self.decoder(latent)
        return reconstructed.view(batch_size, SEQ_LEN, NUM_FEATURES)


# CƠ CHẾ ATTENTION
class AttentionLayer(nn.Module):
    def __init__(self, hidden_size):
        super(AttentionLayer, self).__init__()
        self.attention = nn.Linear(hidden_size, 1, bias=False)

    def forward(self, gru_outputs):
        scores = self.attention(gru_outputs).squeeze(2) 
        alphas = torch.softmax(scores, dim=-1) 
        context = torch.bmm(alphas.unsqueeze(1), gru_outputs).squeeze(1)
        return context, alphas


# KIẾN TRÚC 2: MẠNG LÕI CNN + GRU + ATTENTION (PHÂN LOẠI DDOS)
class DDos_CNN_GRU_Attention(nn.Module):
    def __init__(self):
        super(DDos_CNN_GRU_Attention, self).__init__()
        
        self.conv1 = nn.Conv1d(in_channels=NUM_FEATURES, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.relu = nn.ReLU()
        self.dropout_cnn = nn.Dropout(0.2)
        
        self.gru = nn.GRU(input_size=64, hidden_size=128, num_layers=2, batch_first=True, dropout=0.3)
        self.attention = AttentionLayer(hidden_size=128)
        
        self.fc1 = nn.Linear(128, 64)
        self.bn2 = nn.BatchNorm1d(64)
        self.dropout_fc = nn.Dropout(0.4)
        self.fc2 = nn.Linear(64, NUM_CLASSES)

    def forward(self, x):
        x = x.permute(0, 2, 1) 
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.dropout_cnn(x)
        
        x = x.permute(0, 2, 1) 
        gru_out, _ = self.gru(x)
        
        context, attn_weights = self.attention(gru_out)
        
        x = self.fc1(context)
        x = self.bn2(x)
        x = self.relu(x)
        x = self.dropout_fc(x)
        out = self.fc2(x)
        
        return out, attn_weights