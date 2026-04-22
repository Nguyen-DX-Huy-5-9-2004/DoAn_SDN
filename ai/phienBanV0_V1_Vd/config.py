# Tên file: config.py
'''import torch
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

# --- KIẾN TRÚC LAI CNN + GRU ---
class DDos_CNN_GRU(nn.Module):
    def __init__(self):
        super(DDos_CNN_GRU, self).__init__()
        
        # LỚP CNN: Rút trích đặc trưng không gian
        # Input shape: (Batch, Features, Seq_Len)
        self.conv1 = nn.Conv1d(in_channels=NUM_FEATURES, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.relu = nn.ReLU()
        self.dropout_cnn = nn.Dropout(0.2)
        
        # LỚP GRU: Học hành vi theo thời gian
        self.gru = nn.GRU(input_size=64, hidden_size=128, num_layers=2, batch_first=True, dropout=0.3)
        
        # LỚP PHÂN LOẠI (Classifier)
        self.fc1 = nn.Linear(128, 64)
        self.bn2 = nn.BatchNorm1d(64)
        self.dropout_fc = nn.Dropout(0.4)
        self.fc2 = nn.Linear(64, NUM_CLASSES)

    def forward(self, x):
        # x shape: (Batch, Seq_Len, Features)
        # Biến đổi x -> (Batch, Features, Seq_Len) cho CNN
        x = x.permute(0, 2, 1) 
        
        # Đi qua CNN
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.dropout_cnn(x)
        
        # Biến đổi lại cho GRU -> (Batch, Seq_Len, Channels)
        x = x.permute(0, 2, 1)
        
        # Đi qua GRU
        gru_out, _ = self.gru(x)
        
        # Chỉ lấy trạng thái ẩn ở bước thời gian cuối cùng
        last_out = gru_out[:, -1, :] 
        
        # Phân loại
        x = self.fc1(last_out)
        x = self.bn2(x)
        x = self.relu(x)
        x = self.dropout_fc(x)
        out = self.fc2(x)
        return out'''

#v2
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

# =====================================================================
# 🧠 KIẾN TRÚC 1: MẠNG AUTOENCODER (BẮT ZERO-DAY ANOMALY)
# =====================================================================
class Anomaly_Autoencoder(nn.Module):
    def __init__(self):
        super(Anomaly_Autoencoder, self).__init__()
        input_dim = NUM_FEATURES * SEQ_LEN # 20 * 10 = 200
        
        # ENCODER: Ép nén luồng mạng bình thường để tìm ra quy luật cốt lõi
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32) # Không gian Latent (Bản chất 32 chiều của traffic sạch)
        )
        
        # DECODER: Cố gắng bung nén (phục hồi) lại dữ liệu ban đầu
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim)
        )

    def forward(self, x):
        # Biến đổi x từ (Batch, Seq_len, Features) thành Vector 1D (Batch, 200)
        batch_size = x.size(0)
        x_flat = x.view(batch_size, -1)
        
        # Nén và Giải nén
        latent = self.encoder(x_flat)
        reconstructed = self.decoder(latent)
        
        # Trả về hình dáng nguyên bản (Batch, 10, 20) để tính Sai số tái tạo (Reconstruction Loss)
        return reconstructed.view(batch_size, SEQ_LEN, NUM_FEATURES)


# =====================================================================
# 👁️ CƠ CHẾ ATTENTION (SỰ TẬP TRUNG)
# =====================================================================
class AttentionLayer(nn.Module):
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
        
        # Trả về Context (để phân loại) và Alphas (để sau này vẽ biểu đồ giải thích AI)
        return context, alphas


# =====================================================================
# 🛡️ KIẾN TRÚC 2: MẠNG LÕI CNN + GRU + ATTENTION (PHÂN LOẠI DDOS)
# =====================================================================
class DDos_CNN_GRU_Attention(nn.Module):
    def __init__(self):
        super(DDos_CNN_GRU_Attention, self).__init__()
        
        # LỚP CNN: Rút trích đặc trưng không gian
        self.conv1 = nn.Conv1d(in_channels=NUM_FEATURES, out_channels=64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.relu = nn.ReLU()
        self.dropout_cnn = nn.Dropout(0.2)
        
        # LỚP GRU: Học hành vi theo thời gian
        self.gru = nn.GRU(input_size=64, hidden_size=128, num_layers=2, batch_first=True, dropout=0.3)
        
        # LỚP ATTENTION: Khắc phục điểm yếu "nhìn cào bằng" của GRU cũ
        self.attention = AttentionLayer(hidden_size=128)
        
        # LỚP PHÂN LOẠI (Classifier)
        self.fc1 = nn.Linear(128, 64)
        self.bn2 = nn.BatchNorm1d(64)
        self.dropout_fc = nn.Dropout(0.4)
        self.fc2 = nn.Linear(64, NUM_CLASSES)

    def forward(self, x):
        # x shape: (Batch, Seq_Len, Features)
        
        # --- CNN BLOCK ---
        x = x.permute(0, 2, 1) # -> (Batch, Features, Seq_Len)
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu(x)
        x = self.dropout_cnn(x)
        
        # --- GRU BLOCK ---
        x = x.permute(0, 2, 1) # -> (Batch, Seq_Len, Channels)
        gru_out, _ = self.gru(x)
        
        # --- ATTENTION BLOCK ---
        # Thay vì chỉ lấy last_out như trước, giờ ta lấy Context Vector tinh hoa nhất
        context, attn_weights = self.attention(gru_out)
        
        # --- CLASSIFIER BLOCK ---
        x = self.fc1(context)
        x = self.bn2(x)
        x = self.relu(x)
        x = self.dropout_fc(x)
        out = self.fc2(x)
        
        # Lưu ý: Model giờ sẽ trả về cả kết quả phân loại lẫn trọng số Attention
        return out, attn_weights