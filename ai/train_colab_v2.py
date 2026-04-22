# Tên file: train_colab_v2.py - Nâng cấp với Contrastive Learning & Differential Features
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
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

BATCH_SIZE = 256
EPOCHS_AE = 30      # Autoencoder epochs
EPOCHS_CLS = 50     # Classifier epochs
LEARNING_RATE = 0.001


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
    def __init__(self, sequences, labels, augment=False):
        self.sequences = torch.FloatTensor(sequences)
        self.labels = torch.LongTensor(labels)
        self.augment = augment

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        x = self.sequences[idx]
        y = self.labels[idx]
        
        # Augmentation: Gaussian noise + random scaling
        if self.augment:
            if random.random() > 0.5:
                x = x + torch.randn_like(x) * 0.01 
            if random.random() > 0.5:
                x = x * (0.9 + random.random() * 0.2)
        
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
            batch_X, batch_y = batch_X.to(device), batch_y.to(device) # Chú ý phải load cả batch_y lên GPU
            
            optimizer.zero_grad()
            
            # Forward pass
            recon, latent = ae_model(batch_X)
            
            # 1. Tính MSE cho TỪNG MẪU trong batch (dim 1, 2)
            mse_per_sample = torch.mean((recon - batch_X) ** 2, dim=(1, 2))
            
            # 2. CONTRASTIVE LOGIC: Phân tách Normal và Attack
            margin = 1.0 # Ngưỡng đẩy ra xa
            
            # Mẫu Normal (y == 0): Ép MSE xuống càng thấp càng tốt
            loss_normal = mse_per_sample[batch_y == 0].mean() if (batch_y == 0).any() else torch.tensor(0.0).to(device)
            
            # Mẫu Attack (y != 0): Đẩy MSE lên cao, ép nó phải lớn hơn margin
            loss_attack = torch.clamp(margin - mse_per_sample[batch_y != 0], min=0.0).mean() if (batch_y != 0).any() else torch.tensor(0.0).to(device)
            
            # Thêm L2 regularization trên latent space để chống overfit
            latent_l2 = torch.mean(latent ** 2)
            
            # 3. Tổng hợp Loss
            loss = loss_normal + (loss_attack * 2.0) + (0.001 * latent_l2) # Nhân đôi phạt cho Attack
            
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


def compute_ae_threshold(ae_model, normal_data, device, percentile=95):
    """
    Tính ngưỡng Reconstruction Error từ dữ liệu normal
    """
    ae_model.eval()
    errors = []
    
    with torch.no_grad():
        for i in range(0, len(normal_data), BATCH_SIZE):
            batch = normal_data[i : i + BATCH_SIZE].to(device)
            recon, _ = ae_model(batch)
            
            batch_flat = batch.view(batch.size(0), -1)
            recon_flat = recon.view(recon.size(0), -1)
            
            error = torch.mean((batch_flat - recon_flat) ** 2, dim=1)
            errors.extend(error.cpu().numpy())
    
    errors = np.array(errors)
    threshold = np.percentile(errors, percentile)
    
    print(f"[*] Reconstruction Error Statistics:")
    print(f"    Min: {errors.min():.6f}, Max: {errors.max():.6f}")
    print(f"    Mean: {errors.mean():.6f}, Std: {errors.std():.6f}")
    print(f"    Ngưỡng ({percentile}th percentile): {threshold:.6f}\n")
    
    return threshold


def train_classifier(model, train_loader, val_loader, device, class_weights, epochs=EPOCHS_CLS):
    """
    Huấn luyện Classifier (CNN-GRU song song)
    """
    criterion = FocalLoss(alpha=1, gamma=2.5, weight=class_weights)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
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
        
        if (epoch + 1) % 5 == 0:
            print(f"  Epoch {epoch+1}/{epochs} | Train Acc: {train_acc:.2%} | Val Acc: {val_acc:.2%} | LR: {optimizer.param_groups[0]['lr']:.6f}")
        
        if val_acc > best_acc:
            best_acc = val_acc
            torch.save(model.state_dict(), 'sdn_model_parallel_fusion.pth')
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= 15:
                print("  [!] Early stopping kích hoạt!")
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
    print(f"\n  Classification Report:")
    print(classification_report(cls_labels, cls_preds, target_names=list(LABEL_NAMES.values())))


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

    DATASET_PATH = "/content/drive/MyDrive/SDN_Project/master_dataset_v6.csv"
    
    if not os.path.exists(DATASET_PATH):
        print(f"[!] LỖI: Không tìm thấy dataset tại {DATASET_PATH}")
        print("    Vui lòng kiểm tra lại đường dẫn trên Google Drive!")
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
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_seq, y_seq, test_size=0.2, stratify=y_seq, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )
    
    # ===== SCALING FIX: Fit scaler với 26 features (13 gốc + 13 differential) =====
    # CRITICAL: Phải khớp với inference trong run_onos_v2.py line 287-289
    scaler = StandardScaler()
    
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
    train_dataset = SDNFlowDataset(X_train_final, y_train, augment=True)
    val_dataset = SDNFlowDataset(X_val_final, y_val, augment=False)
    test_dataset = SDNFlowDataset(X_test_final, y_test, augment=False)
    
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
    
    # Compute AE threshold
    X_train_normal = X_train_final[y_train == 0]
    ae_threshold = compute_ae_threshold(ae_model, X_train_normal, DEVICE, percentile=95)
    joblib.dump(ae_threshold, 'ae_threshold.pkl')
    
    # Train Phase 2: Classifier
    unique_classes = np.unique(y_train)
    weights_dict = compute_class_weight('balanced', classes=unique_classes, y=y_train)
    
    # Đảm bảo tensor luôn có kích thước là 5 (NUM_CLASSES)
    weights_array = np.ones(NUM_CLASSES)
    for i, cls in enumerate(unique_classes):
        weights_array[int(cls)] = weights_dict[i]
        
    class_weights = torch.FloatTensor(weights_array).to(DEVICE)
    
    train_classifier(cls_model, train_loader, val_loader, DEVICE, class_weights, epochs=EPOCHS_CLS)
    
    # Evaluation
    evaluate_models(ae_model, cls_model, X_test_final, torch.LongTensor(y_test), ae_threshold, DEVICE)
    
    print("\n✓ Huấn luyện hoàn thành!")
    print(f"  - Autoencoder: sdn_autoencoder_contrastive.pth")
    print(f"  - Classifier: sdn_model_parallel_fusion.pth")
    print(f"  - Scaler: sdn_scaler.pkl")
    print(f"  - Threshold: ae_threshold.pkl")
