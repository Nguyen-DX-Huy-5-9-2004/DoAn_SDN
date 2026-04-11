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
        return out