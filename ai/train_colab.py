# Tên file: train_colab.py
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time
import os
import random

# IMPORT CÁC MÔ HÌNH NÂNG CẤP
from config import (
    Anomaly_Autoencoder, DDos_Residual_CNN_GRU_Attention, 
    NUM_FEATURES, SEQ_LEN, LABEL_NAMES, NUM_CLASSES 
)

# --- 0. CÔNG CỤ NÂNG CẤP: FOCAL LOSS & FEATURE ENGINEERING ---
class FocalLoss(nn.Module):
    def __init__(self, alpha=1, gamma=2, weight=None):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.weight = weight
        self.ce = nn.CrossEntropyLoss(weight=weight, reduction='none')

    def forward(self, inputs, targets):
        ce_loss = self.ce(inputs, targets)
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt)**self.gamma * ce_loss
        return focal_loss.mean()

def differential_features(X):
    """Tính toán sự thay đổi giữa các flow liên tiếp (Differential Features)"""
    # X: [Batch, Seq, Features]
    diff = torch.zeros_like(X)
    diff[:, 1:, :] = X[:, 1:, :] - X[:, :-1, :]
    return torch.cat([X, diff], dim=-1) # Trả về gấp đôi số đặc trưng nếu cần, 
                                        # nhưng ở đây chúng ta sẽ tích hợp vào model hoặc tiền xử lý

# --- 1. THIẾT LẬP MÔI TRƯỜNG ---
def seed_everything(seed=42):
    random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.backends.cudnn.deterministic = True 

seed_everything(42)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BATCH_SIZE = 512 
EPOCHS_AE = 20   
EPOCHS_CLS = 40  

# --- 2. XỬ LÝ DỮ LIỆU L3-OPTIMIZED ---
class SDNFlowDataset(Dataset):
    def __init__(self, sequences, labels, augment=False):
        self.sequences = torch.FloatTensor(sequences)
        self.labels = torch.LongTensor(labels)
        self.augment = augment

    def __len__(self): return len(self.labels)

    def __getitem__(self, idx):
        x = self.sequences[idx]
        y = self.labels[idx]
        
        # AUGMENTATION: Thêm nhiễu Gaussian và Scaling ngẫu nhiên
        # Giúp mô hình chịu tải tốt hơn với biến động jitter/latency mạng L3
        if self.augment:
            if random.random() > 0.5:
                x = x + torch.randn_like(x) * 0.01 
            if random.random() > 0.5:
                x = x * (0.9 + random.random() * 0.2) # Scale +/- 10%
        return x, y

def create_sequences(features, labels, seq_len, stride=2, downsample_ratio=0.1):
    """
    Tạo chuỗi thời gian kết hợp Sequence-based Stratified Downsampling.
    Giảm bớt các chuỗi Flood giống hệt nhau nhưng giữ lại tính 'dồn dập'.
    """
    print(f"⏳ Đang tạo chuỗi thời gian (Stride={stride}, Downsample={downsample_ratio})...")
    X, y = [], []
    
    # Bộ đệm để theo dõi tính 'tĩnh' của chuỗi (cho Downsampling)
    flood_signatures = {} # {(label, port, proto, packet_rate_rounded): count}

    for i in range(0, len(features) - seq_len, stride):
        window_features = features[i : i + seq_len]
        window_labels = labels[i : i + seq_len]
        
        # Chỉ lấy chuỗi nếu nhãn đồng nhất (tránh nhiễu ranh giới)
        if np.all(window_labels == window_labels[0]):
            label = window_labels[-1]
            
            # Nếu là tấn công (label != 0), áp dụng Stratified Downsampling
            if label != 0:
                # Tạo signature dựa trên các đặc trưng 'tĩnh' và tốc độ
                # Cột 1: Dst_Port, Cột 2: Protocol, Cột 10: Packet_Rate
                sig = (label, window_features[0, 1], window_features[0, 2], round(window_features[0, 10], -2))
                
                if sig not in flood_signatures:
                    flood_signatures[sig] = 0
                
                flood_signatures[sig] += 1
                
                # Chỉ giữ lại theo tỉ lệ nhất định nếu chuỗi quá giống nhau (bụng của đợt Flood)
                # Nhưng luôn giữ lại các chuỗi ở 'điểm bắt đầu' (count thấp)
                if flood_signatures[sig] > 100 and random.random() > downsample_ratio:
                    continue

            X.append(window_features)
            y.append(label)
            
    X = np.array(X)
    y = np.array(y)
    
    # Tích hợp Differential Features: Tính sự thay đổi giữa các flow (t - t-1)
    print(f"⚙️ Đang trích xuất Đặc trưng biến thiên (Differential Features)...")
    # X shape: [Batch, Seq, Features]
    diff = np.zeros_like(X)
    diff[:, 1:, :] = X[:, 1:, :] - X[:, :-1, :]
    
    # Kết hợp Đặc trưng gốc và Đặc trưng biến thiên
    X_combined = np.concatenate([X, diff], axis=-1)
    
    return X_combined, y

# --- 3. PIPELINE HUẤN LUYỆN ---
def train_autoencoder(ae_model, train_loader, device):
    criterion = nn.MSELoss()
    optimizer = optim.Adam(ae_model.parameters(), lr=0.001)
    
    print("\n[PHA 1] Huấn luyện Khiên 1: Autoencoder")
    for epoch in range(EPOCHS_AE):
        ae_model.train()
        losses = []
        for batch_X in train_loader:
            batch_X = batch_X[0].to(device)
            optimizer.zero_grad()
            recon = ae_model(batch_X)
            loss = criterion(recon, batch_X)
            loss.backward()
            optimizer.step()
            losses.append(loss.item())
        if (epoch+1) % 5 == 0:
            print(f"  Epoch {epoch+1}/{EPOCHS_AE} | Loss: {np.mean(losses):.6f}")

def train_classifier(model, train_loader, val_loader, device, weights):
    criterion = FocalLoss(alpha=1, gamma=2, weight=weights)
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=3)
    
    print("\n[PHA 2] Huấn luyện Khiên 2: Residual CNN-GRU-Attention")
    best_acc = 0
    patience_counter = 0
    
    for epoch in range(EPOCHS_CLS):
        model.train()
        train_losses = []
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            optimizer.zero_grad()
            outputs, _, _ = model(batch_X) # Nhận thêm weights từ Spatial-Temporal Attention
            loss = criterion(outputs, batch_y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_losses.append(loss.item())
            
        # Validation
        model.eval()
        correct, total = 0, 0
        with torch.no_grad():
            for b_X, b_y in val_loader:
                b_X, b_y = b_X.to(device), b_y.to(device)
                out, _, _ = model(b_X)
                _, pred = torch.max(out, 1)
                total += b_y.size(0)
                correct += (pred == b_y).sum().item()
        
        val_acc = 100 * correct / total
        scheduler.step(val_acc)
        
        print(f"  Epoch {epoch+1}/{EPOCHS_CLS} | Val Acc: {val_acc:.2f}% | LR: {optimizer.param_groups[0]['lr']:.6f}")
        
        if val_acc > best_acc:
            best_acc = val_acc
            torch.save(model.state_dict(), 'sdn_model_cnn_gru_attn.pth')
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 10:
                print("  Early stopping kích hoạt!")
                break

# --- 4. MAIN ---
if __name__ == "__main__":
    DATASET_PATH = "master_dataset_v6.csv"
    if not os.path.exists(DATASET_PATH):
        print(f"[!] Không tìm thấy {DATASET_PATH}. Đang thử với v5...")
        DATASET_PATH = "master_dataset_v5.csv"
        if not os.path.exists(DATASET_PATH):
            print(f"[!] Không tìm thấy dữ liệu. Vui lòng chuẩn bị dữ liệu trước.")
            exit()

    print("[*] Đang nạp dữ liệu...")
    df = pd.read_csv(DATASET_PATH).dropna()
    
    # --- CHIẾN THUẬT DỮ LIỆU: Sequence-based Stratified Downsampling ---
    print("[*] Áp dụng Stratified Downsampling cho các lớp Flood...")
    df_benign = df[df['target_label'] == 0]
    df_attacks = df[df['target_label'] != 0]
    
    # Downsample các lớp tấn công nếu quá nhiều (giữ lại tính đa dạng)
    sampled_attacks = []
    for label in range(1, 5):
        df_label = df[df['target_label'] == label]
        if len(df_label) > 20000:
            df_label = df_label.sample(n=20000, random_state=42)
        sampled_attacks.append(df_label)
    
    df = pd.concat([df_benign] + sampled_attacks).sample(frac=1).reset_index(drop=True)
    label_col = 'target_label'
    X_raw = df.drop(columns=[label_col]).values
    y_raw = df[label_col].values

    X_seq, y_seq = create_sequences(X_raw, y_raw, SEQ_LEN)
    
    # Chia tập
    X_train, X_test, y_train, y_test = train_test_split(X_seq, y_seq, test_size=0.2, stratify=y_seq)
    
    # Scaling
    scaler = StandardScaler()
    # Tính toán scaler trên dữ liệu gốc (không bao gồm diff vì diff sẽ được tính sau khi scale để đảm bảo tính khách quan)
    X_train_raw = X_train[:, :, :NUM_FEATURES]
    X_test_raw = X_test[:, :, :NUM_FEATURES]
    
    X_train_scaled_raw = scaler.fit_transform(X_train_raw.reshape(-1, NUM_FEATURES)).reshape(-1, SEQ_LEN, NUM_FEATURES)
    X_test_scaled_raw = scaler.transform(X_test_raw.reshape(-1, NUM_FEATURES)).reshape(-1, SEQ_LEN, NUM_FEATURES)
    
    # Tính lại Differential Features trên dữ liệu đã scale
    def get_diff_tensor(tensor):
        diff = torch.zeros_like(tensor)
        diff[:, 1:, :] = tensor[:, 1:, :] - tensor[:, :-1, :]
        return torch.cat([tensor, diff], dim=-1)

    X_train_final = get_diff_tensor(torch.FloatTensor(X_train_scaled_raw))
    X_test_final = get_diff_tensor(torch.FloatTensor(X_test_scaled_raw))
    
    joblib.dump(scaler, 'sdn_scaler.pkl')

    # Train AE (Contrastive Learning Approach - Prepare pairs)
    # Lấy dữ liệu Normal
    X_ae_normal = X_train_final[y_train == 0]
    # Lấy một ít dữ liệu Attack để học tương phản
    X_ae_attack = X_train_final[y_train != 0][:len(X_ae_normal)//4]
    
    # Dataset đặc biệt cho AE Contrastive
    class ContrastiveAEDataset(Dataset):
        def __init__(self, normal_data, attack_data):
            self.normal_data = normal_data
            self.attack_data = attack_data
        def __len__(self): return len(self.normal_data)
        def __getitem__(self, idx):
            # Trả về 1 mẫu normal và 1 label (0 cho normal)
            # Thỉnh thoảng trả về mẫu attack với label 1 để học đẩy ra xa
            if random.random() > 0.8 and len(self.attack_data) > 0:
                return self.attack_data[random.randint(0, len(self.attack_data)-1)], 1
            return self.normal_data[idx], 0

    ae_loader = DataLoader(ContrastiveAEDataset(X_ae_normal, X_ae_attack), batch_size=BATCH_SIZE, shuffle=True)
    ae_model = Anomaly_Autoencoder(input_dim=NUM_FEATURES * 2).to(DEVICE) # Input_dim gấp đôi do có diff features
    
    # Cập nhật hàm train_autoencoder để hỗ trợ Contrastive/Triplet Loss
    def train_autoencoder_contrastive(model, loader, device):
        optimizer = optim.Adam(model.parameters(), lr=0.001)
        # MSE cho reconstruction, nhưng thêm penalty nếu attack bị reconstruct quá tốt
        mse_loss = nn.MSELoss(reduction='none')
        
        print("\n[PHA 1] Huấn luyện Khiên 1: Contrastive Autoencoder")
        for epoch in range(EPOCHS_AE):
            model.train()
            total_loss = 0
            for batch_X, batch_y in loader:
                batch_X, batch_y = batch_X.to(device), batch_y.to(device)
                optimizer.zero_grad()
                recon = model(batch_X)
                
                # Tính MSE cho từng mẫu trong batch
                loss_per_sample = mse_loss(recon, batch_X).mean(dim=(1,2))
                
                # Contrastive Logic: 
                # Nếu là Normal (y=0): cực tiểu hóa loss (kéo lại gần)
                # Nếu là Attack (y=1): cực đại hóa loss (đẩy ra xa) đến một ngưỡng margin
                loss = torch.where(batch_y == 0, 
                                   loss_per_sample, 
                                   torch.clamp(1.0 - loss_per_sample, min=0)).mean()
                
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            if (epoch+1) % 5 == 0:
                print(f"  Epoch {epoch+1}/{EPOCHS_AE} | Loss: {total_loss/len(loader):.6f}")

    train_autoencoder_contrastive(ae_model, ae_loader, DEVICE)
    
    # Tính ngưỡng AE
    ae_model.eval()
    with torch.no_grad():
        recon = ae_model(torch.FloatTensor(X_ae).to(DEVICE))
        mse = torch.mean((torch.FloatTensor(X_ae).to(DEVICE) - recon)**2, dim=(1,2)).cpu().numpy()
        threshold = np.mean(mse) + 3 * np.std(mse)
        joblib.dump(threshold, 'ae_threshold.pkl')
        torch.save(ae_model.state_dict(), 'sdn_autoencoder.pth')

    # Train Classifier
    weights = torch.FloatTensor(compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)).to(DEVICE)
    train_loader = DataLoader(SDNFlowDataset(X_train_final, y_train, augment=True), batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(SDNFlowDataset(X_test_final, y_test), batch_size=BATCH_SIZE)
    
    cls_model = DDos_Residual_CNN_GRU_Attention(input_dim=NUM_FEATURES * 2).to(DEVICE)
    train_classifier(cls_model, train_loader, val_loader, DEVICE, weights)

    print("\n[🎯] Hoàn tất huấn luyện. Pipeline AI đã sẵn sàng!")