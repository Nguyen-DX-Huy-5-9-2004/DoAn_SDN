# Tên file: train_colab_v2.py - Nâng cấp với Contrastive Learning & Differential Features
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, TensorDataset
from sklearn.preprocessing import MinMaxScaler # Thay RobustScaler bằng MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time
import os
import random

# IMPORT CÁC MÔ HÌNH NÂNG CẤP từ config_v2
from config_v2 import (
    Anomaly_Autoencoder_Contrastive, DDos_ParallelFusion_CNN_GRU_Attention,
    NUM_FEATURES, NUM_FEATURES_DIFF, NUM_FEATURES_TOTAL, SEQ_LEN, 
    LABEL_NAMES, NUM_CLASSES, FEATURE_NAMES
)

# =====================================================================
# PHẦN 1: CÁC HÀM LOSS NÂNG CẤP
# =====================================================================

class TripletLoss(nn.Module):
    """
    Triplet Loss cho Contrastive Learning của Autoencoder:
    - Anchor (Normal): Reconstruct tốt, MSE thấp
    - Positive (Normal khác): Tương tự Anchor
    - Negative (Attack): Reconstruct tệ, MSE cao
    
    Mục tiêu: distance(anchor, positive) < distance(anchor, negative) - margin
    """
    def __init__(self, margin=1.0):
        super(TripletLoss, self).__init__()
        self.margin = margin
        self.mse = nn.MSELoss(reduction='none')

    def forward(self, ae_model, anchor, positive, negative):
        """
        anchor: Normal flow [B, S, F]
        positive: Another normal flow [B, S, F]
        negative: Attack flow [B, S, F]
        """
        batch_size = anchor.size(0)
        anchor_flat = anchor.view(batch_size, -1)
        positive_flat = positive.view(batch_size, -1)
        negative_flat = negative.view(batch_size, -1)

        # Lấy latent representation từ encoder
        with torch.no_grad():
            _, anchor_latent = ae_model(anchor)
            _, positive_latent = ae_model(positive)
            _, negative_latent = ae_model(negative)

        # Tính khoảng cách Euclidean trong latent space
        pos_dist = torch.norm(anchor_latent - positive_latent, dim=1)
        neg_dist = torch.norm(anchor_latent - negative_latent, dim=1)

        # Triplet loss: max(0, pos_dist - neg_dist + margin)
        loss = torch.clamp(pos_dist - neg_dist + self.margin, min=0.0).mean()

        return loss


class ContrastiveLoss(nn.Module):
    """
    Contrastive Loss: Đơn giản hơn Triplet Loss
    - Cặp cùng lớp (Normal-Normal): Minimize distance
    - Cặp khác lớp (Normal-Attack): Maximize distance
    """
    def __init__(self, margin=1.0, weight_anomaly=2.0):
        super(ContrastiveLoss, self).__init__()
        self.margin = margin
        self.weight_anomaly = weight_anomaly

    def forward(self, ae_model, x1, x2, y):
        """
        x1, x2: Hai dữ liệu để so sánh [B, S, F]
        y: Label 0 (cùng loại - cả hai normal) / 1 (khác loại - một normal, một attack)
        """
        batch_size = x1.size(0)
        x1_flat = x1.view(batch_size, -1)
        x2_flat = x2.view(batch_size, -1)

        # MSE reconstruction error cho từng dữ liệu
        recon1, _ = ae_model(x1)
        recon2, _ = ae_model(x2)
        recon1_flat = recon1.view(batch_size, -1)
        recon2_flat = recon2.view(batch_size, -1)

        # Tính MSE từng mẫu
        error1 = torch.mean((x1_flat - recon1_flat) ** 2, dim=1)
        error2 = torch.mean((x2_flat - recon2_flat) ** 2, dim=1)

        # Contrastive: Nếu cùng loại (y=0, cả normal) -> error giống nhau
        #              Nếu khác loại (y=1, normal vs attack) -> error khác nhau
        dist = torch.abs(error1 - error2)

        loss = torch.where(
            y == 0,
            dist ** 2,  # Cùng loại: minimize distance
            torch.clamp(self.margin - dist, min=0.0) ** 2 * self.weight_anomaly  # Khác loại: maximize distance
        ).mean()

        return loss


class FocalLoss(nn.Module):
    """Focal Loss - Ưu tiên các mẫu khó phân loại"""
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


# =====================================================================
# PHẦN 2: HÀM HỖ TRỢ
# =====================================================================

def seed_everything(seed=42):
    """Đặt seed cho tái tạo kết quả"""
    random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.backends.cudnn.deterministic = True 

seed_everything(42)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[*] Thiết bị: {DEVICE}")

# [TỐI ƯU CHO COLAB GPU MẠNH] Tăng epochs và chất lượng, không cần quan tâm tốc độ
BATCH_SIZE = 512    # Tăng batch size để ổn định gradient, tận dụng GPU
EPOCHS_AE = 80      # Tăng từ 30 -> 80 để convergence tốt hơn
EPOCHS_CLS = 100    # Tăng từ 50 -> 100 cho 5-class classification chính xác
LEARNING_RATE = 0.001

# Ngưỡng AE - P99.5 để bao dung với người dùng thật, tránh báo Zero-day sai
AE_THRESHOLD_PERCENTILE = 99.5  # 99.5% Normal được chấp nhận, chỉ 0.5% ngoại lai

# [TỐI ƯU] Tăng margin để phân biệt Normal/Attack rõ ràng hơn
AE_MARGIN = 2.0  # Tăng từ 1.0 -> 2.0 để đẩy Attack xa hơn


def differential_features_numpy(X):
    """
    Tính đặc trưng biến thiên (Differential Features)
    X: [Batch, Seq, Features]
    Trả về: [Batch, Seq, Features*2] (gốc + biến thiên)
    """
    batch_size, seq_len, num_features = X.shape
    diff = np.zeros_like(X)
    diff[:, 1:, :] = X[:, 1:, :] - X[:, :-1, :]  # Tính sự thay đổi
    
    # Ghép gốc và biến thiên
    combined = np.concatenate([X, diff], axis=-1)
    return combined


class SDNFlowDataset(Dataset):
    """Dataset cho DDoS Detection - L3 Optimized"""
    def __init__(self, sequences, labels, is_train=False):
        self.data = torch.FloatTensor(sequences)
        self.labels = torch.LongTensor(labels)
        self.is_train = is_train

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        x = torch.FloatTensor(self.data[idx])
        y = torch.LongTensor(self.labels[idx])
        
        # Tăng nhiễu Gaussian lên 0.1 để AE bao dung hơn với biến động mạng Normal thực tế
        # Việc thêm nhiễu này giúp Shield 1 không bị "False Zero-day" khi traffic thực tế hơi khác lúc thu thập
        if self.is_train and self.labels[idx] == 0:
            noise = torch.randn_like(x) * 0.1
            x = x + noise
        
        return x, y


def create_sequences_with_differential(features, labels, seq_len, stride=2, downsample_ratio=0.1):
    """
    Tạo chuỗi thời gian và tích hợp Differential Features
    X trở thành [Batch, Seq, Features*2]
    """
    print(f"⏳ Đang tạo chuỗi thời gian (Stride={stride}, Downsample={downsample_ratio})...")
    print(f"   Input shape: {features.shape} | Sẽ tính 26 đặc trưng (13 gốc + 13 biến thiên)")
    
    X, y = [], []
    flood_signatures = {}

    for i in range(0, len(features) - seq_len, stride):
        window_features = features[i : i + seq_len]
        window_labels = labels[i : i + seq_len]
        
        # Chỉ lấy chuỗi nếu nhãn đồng nhất
        if np.all(window_labels == window_labels[0]):
            label = window_labels[-1]
            
            # Downsampling cho lớp tấn công
            if label != 0:
                sig = (label, window_features[0, 1], window_features[0, 2], round(window_features[0, 10], -2))
                
                if sig not in flood_signatures:
                    flood_signatures[sig] = 0
                
                flood_signatures[sig] += 1
                
                if flood_signatures[sig] > 100 and random.random() > downsample_ratio:
                    continue

            X.append(window_features)
            y.append(label)
    
    X = np.array(X)
    y = np.array(y)
    
    print(f"   Trước tính Differential: X shape = {X.shape}")
    
    # TÍCH HỢP DIFFERENTIAL FEATURES
    print(f"⚙️  Đang trích xuất Đặc trưng biến thiên (Differential Features)...")
    X_combined = differential_features_numpy(X)
    
    print(f"   Sau tính Differential: X shape = {X_combined.shape} ✓")
    print(f"   Tổng số sequences: {len(y)}")
    
    return X_combined, y


# =====================================================================
# PHẦN 3: PIPELINE HUẤN LUYỆN
# =====================================================================

def train_autoencoder_contrastive(ae_model, train_loader, device, epochs=EPOCHS_AE):
    """
    Huấn luyện Autoencoder với Contrastive/Triplet Loss
    Mục tiêu: Normal -> MSE thấp, Attack -> MSE cao
    """
    optimizer = optim.Adam(ae_model.parameters(), lr=LEARNING_RATE)
    mse_loss = nn.MSELoss(reduction='mean')
    
    # Contrastive Loss thay vì Triplet (đơn giản hơn)
    contrastive = ContrastiveLoss(margin=1.0, weight_anomaly=2.0)
    
    print("\n" + "="*70)
    print("[PHA 1] Huấn luyện Khiên 1: Contrastive Autoencoder")
    print("="*70)
    
    best_loss = float('inf')
    patience_counter = 0
    
    for epoch in range(epochs):
        ae_model.train()
        total_loss = 0
        total_samples = 0
        
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            
            optimizer.zero_grad()
            
            # Forward pass
            recon, latent = ae_model(batch_X)
            
            # Sử dụng SmoothL1Loss (Huber Loss) để chống bùng nổ MSE
            huber_loss = nn.SmoothL1Loss(reduction='none')
            mse_per_sample = torch.mean(huber_loss(recon, batch_X), dim=(1, 2))
            
            # [TỐI ƯU] CONTRASTIVE LOGIC với margin cao hơn để phân biệt rõ ràng
            margin = AE_MARGIN  # Tăng từ 1.0 -> 2.0 để đẩy Attack xa hơn khỏi Normal
            
            # Mẫu Normal (y == 0): Ép MSE xuống thật thấp (reconstruct tốt)
            loss_normal = mse_per_sample[batch_y == 0].mean() if (batch_y == 0).any() else torch.tensor(0.0).to(device)
            
            # [TỐI ƯU] Mẫu Attack (y != 0): Ép MSE cao hơn margin rõ rệt
            # Nếu MSE của Attack < margin -> phạt nặng (Attack đang quá gần Normal)
            attack_mse = mse_per_sample[batch_y != 0]
            # Hinge loss: max(0, margin - attack_mse) - Attack phải có MSE > margin
            loss_attack = torch.clamp(margin - attack_mse, min=0.0).mean() if (batch_y != 0).any() else torch.tensor(0.0).to(device)
            
            # [THÊM] BONUS: Reward Attack có MSE cao (đã tách biệt tốt)
            # Nếu attack_mse > margin*1.5 -> không cần phạt nữa, thậm chí reward
            well_separated = (attack_mse > margin * 1.5).float().mean()
            bonus_separation = -0.1 * well_separated  # Negative loss = reward
            
            # Thêm L2 regularization trên latent space để chống overfit
            latent_l2 = torch.mean(latent ** 2)
            
            # 3. Tổng hợp Loss [TỐI ƯU]: Cân bằng hơn giữa Normal và Attack
            # Giảm weight của Attack từ 2.0 -> 1.5 (vì margin đã tăng đủ mạnh)
            loss = loss_normal + (loss_attack * 1.5) + (0.001 * latent_l2) + bonus_separation
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(ae_model.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item() * batch_X.size(0)
            total_samples += batch_X.size(0)
        
        avg_loss = total_loss / total_samples
        
        if (epoch + 1) % 5 == 0:
            print(f"  Epoch {epoch+1}/{epochs} | Loss: {avg_loss:.6f}")
        
        if avg_loss < best_loss:
            best_loss = avg_loss
            torch.save(ae_model.state_dict(), 'sdn_autoencoder_contrastive.pth')
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 10:
                print("  [!] Early stopping kích hoạt!")
                break
    
    print(f"✓ Huấn luyện Autoencoder hoàn thành! Best loss: {best_loss:.6f}\n")


def compute_ae_threshold(model, dataloader, device):
    model.eval()
    mse_scores = []
    with torch.no_grad():
        for x, y in dataloader:
            x = x.to(device)
            # Chỉ tính ngưỡng trên dữ liệu Normal (y=0)
            x_normal = x[y == 0]
            if len(x_normal) == 0: continue
            
            x_hat, _ = model(x_normal)
            mse = torch.mean((x_normal - x_hat)**2, dim=(1, 2))
            mse_scores.extend(mse.cpu().numpy())
    
    # [TỐI ƯU] Giảm percentile để cân bằng giữa bao dung và phát hiện
    # P99.5 quá bao dung -> dễ miss attack thực
    # P97.0 vừa đủ: 97% Normal được chấp nhận, 3% có thể là Zero-day
    threshold = np.percentile(mse_scores, AE_THRESHOLD_PERCENTILE)
    print(f"📊 Ngưỡng AE mới tính toán (Percentile {AE_THRESHOLD_PERCENTILE}): {threshold:.6f}")
    
    # Tự động lưu threshold để tránh quên
    joblib.dump(threshold, 'ae_threshold.pkl')
    print("  [+] Đã lưu ae_threshold.pkl")
    
    return threshold


def train_classifier(model, train_loader, val_loader, device, class_weights, epochs=EPOCHS_CLS):
    """
    Huấn luyện Classifier (CNN-GRU song song)
    Sử dụng Label Smoothing để tránh "học vẹt" 100% Accuracy.
    """
    # [FIX] Giảm Label Smoothing xuống 0.01 để tránh confusion giữa các lớp
    # Label Smoothing quá cao (0.1) làm model khó phân biệt Normal vs Attack
    criterion = nn.CrossEntropyLoss(weight=class_weights, label_smoothing=0.01)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=5e-3) # [FIX] Tăng weight_decay để giảm overfit
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=5)
    
    print("\n" + "="*70)
    print("[PHA 2] Huấn luyện Khiên 2: Parallel Fusion CNN-GRU-Attention")
    print("="*70)
    
    best_acc = 0
    patience_counter = 0
    
    for epoch in range(epochs):
        model.train()
        train_losses = []
        train_preds = []
        train_labels = []
        
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            
            optimizer.zero_grad()
            
            outputs, _, _ = model(batch_X)
            loss = criterion(outputs, batch_y)
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            train_losses.append(loss.item())
            _, preds = torch.max(outputs, 1)
            train_preds.extend(preds.cpu().numpy())
            train_labels.extend(batch_y.cpu().numpy())
        
        # Validation
        model.eval()
        val_preds = []
        val_labels = []
        val_losses = []
        
        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                batch_X, batch_y = batch_X.to(device), batch_y.to(device)
                outputs, _, _ = model(batch_X)
                loss = criterion(outputs, batch_y)
                
                val_losses.append(loss.item())
                _, preds = torch.max(outputs, 1)
                val_preds.extend(preds.cpu().numpy())
                val_labels.extend(batch_y.cpu().numpy())
        
        train_acc = accuracy_score(train_labels, train_preds)
        val_acc = accuracy_score(val_labels, val_preds)
        
        scheduler.step(val_acc)
        
        # [DEBUG] Log mỗi epoch để theo dõi overfit
        if (epoch + 1) % 1 == 0:
            # Tính accuracy từng lớp trên validation
            from sklearn.metrics import classification_report
            val_class_acc = []
            for c in range(5):
                mask = np.array(val_labels) == c
                if mask.sum() > 0:
                    acc_c = (np.array(val_preds)[mask] == c).mean()
                    val_class_acc.append(f"{c}:{acc_c:.0%}")
            print(f"  Epoch {epoch+1}/{epochs} | Train: {train_acc:.1%} | Val: {val_acc:.1%} | LR: {optimizer.param_groups[0]['lr']:.6f}")
            print(f"    Val per-class: {', '.join(val_class_acc)}")
        
        # [FIX] Giảm patience xuống 10 để dừng sớm khi overfit
        if val_acc > best_acc:
            best_acc = val_acc
            torch.save(model.state_dict(), 'sdn_model_parallel_fusion.pth')
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 10:  # Giảm từ 15 -> 10
                print(f"  [!] Early stopping! Val not improve for 10 epochs. Best: {best_acc:.2%}")
                break
    
    print(f"✓ Huấn luyện Classifier hoàn thành! Best accuracy: {best_acc:.2%}\n")


def evaluate_models(ae_model, cls_model, test_data, test_labels, ae_threshold, device):
    """
    Đánh giá cả Autoencoder và Classifier
    """
    ae_model.eval()
    cls_model.eval()
    
    ae_errors = []
    cls_preds = []
    cls_labels = []
    
    print("\n" + "="*70)
    print("[EVALUATION] Đánh giá mô hình")
    print("="*70)
    
    with torch.no_grad():
        for i in range(0, len(test_data), BATCH_SIZE):
            batch_end = min(i + BATCH_SIZE, len(test_data))
            batch_X = test_data[i:batch_end].to(device)
            batch_y = test_labels[i:batch_end].to(device)
            
            # Autoencoder
            recon, _ = ae_model(batch_X)
            batch_flat = batch_X.view(batch_X.size(0), -1)
            recon_flat = recon.view(recon.size(0), -1)
            error = torch.mean((batch_flat - recon_flat) ** 2, dim=1)
            ae_errors.extend(error.cpu().numpy())
            
            # Classifier
            outputs, _, _ = cls_model(batch_X)
            _, preds = torch.max(outputs, 1)
            cls_preds.extend(preds.cpu().numpy())
            cls_labels.extend(batch_y.cpu().numpy())
    
    # AE Detection Performance
    ae_predictions = (np.array(ae_errors) > ae_threshold).astype(int)
    ae_binary_labels = (test_labels.cpu().numpy() != 0).astype(int)
    
    print("\n📊 AUTOENCODER (Anomaly Detection):")
    print(f"  Reconstruction Error - Mean: {np.mean(ae_errors):.6f}, Std: {np.std(ae_errors):.6f}")
    
    # Classifier Performance
    cls_acc = accuracy_score(cls_labels, cls_preds)
    print(f"\n🎯 CLASSIFIER (DDoS Type Classification):")
    print(f"  Accuracy: {cls_acc:.2%}")
    
    # [DEBUG] Confusion Matrix để thấy rõ model đang nhầm lẫn
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(cls_labels, cls_preds)
    print(f"\n  Confusion Matrix (True vs Pred):")
    print(f"         0:N  1:UDP  2:SYN  3:HTTP 4:SLW")
    for i, row in enumerate(cm):
        print(f"  {i}:{list(LABEL_NAMES.values())[i][:4]:>4s} {row}")
    
    print(f"\n  Classification Report:")
    print(classification_report(cls_labels, cls_preds, target_names=list(LABEL_NAMES.values()), zero_division=0))


# =====================================================================
# PHẦN 4: MAIN
# =====================================================================

if __name__ == "__main__":
    # Tìm dataset
    '''try:
        from google.colab import drive
        drive.mount('/content/drive')
        print("[*] Đã kết nối thành công với Google Drive!")
    except ImportError:
        print("[*] Đang chạy ở local, bỏ qua bước mount Drive.")'''

    # [V7 UPDATE] Dataset path cho phiên bản mới với Port Entropy
    DATASET_PATH = "/content/drive/MyDrive/SDN_Project/master_dataset_v7.csv"
    
    # Fallback cho local testing
    LOCAL_PATH = "/home/tgf/Documents/DoAn_SDN/thuThapData/master_dataset_v7.csv"
    
    # Thử đường dẫn Colab trước, nếu không có thì dùng local
    if not os.path.exists(DATASET_PATH):
        if os.path.exists(LOCAL_PATH):
            DATASET_PATH = LOCAL_PATH
            print(f"[*] Sử dụng local dataset: {DATASET_PATH}")
        else:
            print(f"[!] LỖI: Không tìm thấy dataset tại cả Colab lẫn Local!")
            print(f"    - Colab: /content/drive/MyDrive/SDN_Project/master_dataset_v7.csv")
            print(f"    - Local: {LOCAL_PATH}")
            exit(1)
    
    if not os.path.exists(DATASET_PATH):
        print(f"[!] Không tìm thấy dataset!")
        exit(1)
    
    print(f"[*] Đang nạp dữ liệu từ {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH).dropna()
    print(f"    Loaded {len(df)} rows")
    
    # Chuẩn bị dữ liệu
    print("\n[*] Chuẩn bị dữ liệu chuỗi thời gian...")
    label_col = df.columns[-1]  # Tự động lấy cột cuối cùng làm nhãn
    X_raw = df.drop(columns=[label_col]).values
    y_raw = df[label_col].values
    print(f"    X shape: {X_raw.shape}, y shape: {y_raw.shape}")
    
    # Tạo sequences với Differential Features
    X_seq, y_seq = create_sequences_with_differential(X_raw, y_raw, SEQ_LEN)
    
    # 2. Scaling Fix: Xử lý Log cho dữ liệu cực đoan
    def safe_log(x):
        # SymLog: log(1+|x|) * sign(x) - Giữ nguyên dấu và nén được cả số âm (Differential)
        return np.sign(x) * np.log1p(np.abs(x))

    # Index các cột cần nén: Bytes, Packets, Rates (Đã cập nhật cho 26 features)
    # Gốc: 4(Src_Bytes), 5(Dst_Bytes), 6(Src_Packets), 7(Dst_Packets), 10(Packet_Rate), 11(Byte_Rate)
    # Diff: 17, 18, 19, 20, 23, 24
    cols_to_log = [4, 5, 6, 7, 10, 11, 17, 18, 19, 20, 23, 24] 
    X_seq[:, :, cols_to_log] = safe_log(X_seq[:, :, cols_to_log])

    # Xử lý triệt để NaN hoặc Inf nếu có
    if np.any(np.isnan(X_seq)) or np.any(np.isinf(X_seq)):
        X_seq = np.nan_to_num(X_seq, nan=0.0, posinf=1.0, neginf=-1.0)

    # [V7 UPDATE] Feature Importance Weighting
    # Tập trung vào đặc trưng phân biệt tốt (Duration, Packet_Rate, Byte_Rate)
    # Giảm trọng số Port Entropy (vì giống nhau ở các lớp trong lab)
    print("\n⚖️  Áp dụng Feature Importance Weighting...")
    feature_weights = np.ones(NUM_FEATURES_TOTAL)
    
    # Tăng trọng số cho đặc trưng phân biệt tốt (theo phân tích data v7)
    # Duration (3): Slowloris (19s) vs others (<1s) - RẤT QUAN TRỌNG
    feature_weights[3] = 2.0    # Duration_Sec
    feature_weights[16] = 2.0   # d_Duration_Sec
    
    # Packet_Rate (10): UDP (30k) vs HTTP (80) - RẤT QUAN TRỌNG  
    feature_weights[10] = 2.0   # Packet_Rate
    feature_weights[23] = 2.0   # d_Packet_Rate
    
    # Byte_Rate (11): UDP (24M) vs Normal (639k) - RẤT QUAN TRỌNG
    feature_weights[11] = 1.5   # Byte_Rate
    feature_weights[24] = 1.5   # d_Byte_Rate
    
    # Giảm trọng số Port Entropy (vì giống nhau ở tất cả lớp ~3.32)
    feature_weights[0] = 0.5    # Src_Port_Entropy
    feature_weights[1] = 0.5    # Dst_Port_Entropy
    feature_weights[13] = 0.5   # d_Src_Port_Entropy
    feature_weights[14] = 0.5   # d_Dst_Port_Entropy
    
    # Áp dụng weighting
    X_seq = X_seq * feature_weights
    print(f"  Feature weights: Duration=2.0, Packet_Rate=2.0, Byte_Rate=1.5, Port_Entropy=0.5")
    
    # Lưu feature weights để inference đồng bộ
    joblib.dump(feature_weights, 'feature_weights.pkl')
    print("  [+] Đã lưu feature_weights.pkl")
    
    # [NÂNG CẤP] Port Entropy: Không cần che cổng nữa vì Src_Port/Dst_Port 
    # bây giờ đã là giá trị Entropy (độ hỗn loạn), không phải số hiệu cổng cụ thể.
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_seq, y_seq, test_size=0.2, stratify=y_seq, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )
    
    # Sử dụng MinMaxScaler để ép về dải [0, 1] cho Autoencoder
    scaler = MinMaxScaler()
    
    # X_train shape: [N, S, 26] (already contains 13 gốc + 13 differential từ create_sequences_with_differential)
    # Fit scaler trên ĐẦY ĐỦ 26 features để inference không bị lỗi dimension
    X_train_final = scaler.fit_transform(X_train.reshape(-1, NUM_FEATURES_TOTAL)).reshape(-1, SEQ_LEN, NUM_FEATURES_TOTAL)
    X_test_final = scaler.transform(X_test.reshape(-1, NUM_FEATURES_TOTAL)).reshape(-1, SEQ_LEN, NUM_FEATURES_TOTAL)
    X_val_final = scaler.transform(X_val.reshape(-1, NUM_FEATURES_TOTAL)).reshape(-1, SEQ_LEN, NUM_FEATURES_TOTAL)
    
    X_train_final = torch.FloatTensor(X_train_final)
    X_test_final = torch.FloatTensor(X_test_final)
    X_val_final = torch.FloatTensor(X_val_final)
    
    joblib.dump(scaler, 'sdn_scaler.pkl')
    
    print(f"\n✓ Data preprocessing:")
    print(f"  Train: {X_train_final.shape}")
    print(f"  Val: {X_val_final.shape}")
    print(f"  Test: {X_test_final.shape}")
    
    # Chuẩn bị DataLoader
    train_dataset = SDNFlowDataset(X_train_final, y_train, is_train=True)
    val_dataset = SDNFlowDataset(X_val_final, y_val, is_train=False)
    test_dataset = SDNFlowDataset(X_test_final, y_test, is_train=False)
    
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    # Initialize models
    print(f"\n[*] Khởi tạo mô hình trên {DEVICE}...")
    ae_model = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN).to(DEVICE)
    cls_model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL).to(DEVICE)
    
    print(f"  Autoencoder: {sum(p.numel() for p in ae_model.parameters()):,} parameters")
    print(f"  Classifier: {sum(p.numel() for p in cls_model.parameters()):,} parameters")
    
    # Train Phase 1: Autoencoder
    train_autoencoder_contrastive(ae_model, train_loader, DEVICE, epochs=EPOCHS_AE)
    
    # Compute AE threshold (Sử dụng toàn bộ dữ liệu train để lọc lấy normal bên trong hàm)
    ae_threshold = compute_ae_threshold(ae_model, train_loader, DEVICE)
    
    # Train Phase 2: Classifier
    # [FIX] Không dùng 'balanced' weights vì Normal có nhiều mẫu nhất -> weight thấp nhất
    # Dùng equal weights để model học đều tất cả classes
    print(f"\n[DEBUG] Class distribution in y_train: {np.bincount(y_train.astype(int), minlength=5)}")
    print(f"[DEBUG] Class distribution in y_val: {np.bincount(y_val.astype(int), minlength=5)}")
    print(f"[DEBUG] Class distribution in y_test: {np.bincount(y_test.astype(int), minlength=5)}")
    
    # Equal weights - mọi class đều quan trọng như nhau
    class_weights = torch.ones(NUM_CLASSES).to(DEVICE)
    print(f"[INFO] Using equal class weights: {class_weights}")
    
    train_classifier(cls_model, train_loader, val_loader, DEVICE, class_weights, epochs=EPOCHS_CLS)
    
    # Evaluation
    evaluate_models(ae_model, cls_model, X_test_final, torch.LongTensor(y_test), ae_threshold, DEVICE)
    
    print("\n✓ Huấn luyện hoàn thành!")
    print(f"  - Autoencoder: sdn_autoencoder_contrastive.pth")
    print(f"  - Classifier: sdn_model_parallel_fusion.pth")
    print(f"  - Scaler: sdn_scaler.pkl")
    print(f"  - Threshold: ae_threshold.pkl")
    print(f"  - Feature Weights: feature_weights.pkl")
    print(f"\n[V7 CONFIG] Đã tối ưu cho dataset v7:")
    print(f"  - Duration, Packet_Rate, Byte_Rate: x2.0 weight")
    print(f"  - Port Entropy: x0.5 weight (giảm ảnh hưởng)")
    print(f"  - Logic 2-Shield: Bảo vệ Normal tuyệt đối (>80% Normal = TIN)")
