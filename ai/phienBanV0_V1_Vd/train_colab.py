# Tên file: train_colab.py
'''import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time

from config import DDos_CNN_GRU, NUM_FEATURES, SEQ_LEN, LABEL_NAMES, NUM_CLASSES 

# 1. THIẾT LẬP THÔNG SỐ
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BATCH_SIZE = 512
EPOCHS = 20

print(f"🚀 Đang train trên thiết bị: {DEVICE}")

# 2. DATASET VÀ CỬA SỔ TRƯỢT AN TOÀN
class SDNFlowDataset(Dataset):
    def __init__(self, sequences, labels):
        self.sequences = torch.FloatTensor(sequences)
        self.labels = torch.LongTensor(labels)
    def __len__(self): return len(self.labels)
    def __getitem__(self, idx): return self.sequences[idx], self.labels[idx]

def create_safe_sequences(features, labels, seq_len):
    """Cửa sổ trượt CHỈ GỘP KHI ĐỒNG NHẤT NHÃN (Chống Data Leakage)"""
    print(f"⏳ Đang tạo chuỗi Time-Series (Seq_len = {seq_len})...")
    X, y = [], []
    stride = seq_len # Nhảy đủ 10 bước để Train/Test độc lập hoàn toàn
    
    for i in range(0, len(features) - seq_len, stride):
        window_labels = labels[i : i + seq_len]
        if np.all(window_labels == window_labels[0]):
            X.append(features[i : i + seq_len])
            y.append(window_labels[-1])
            
    return np.array(X), np.array(y)

# 3. MẠCH CHÍNH
if __name__ == "__main__":
    # ĐỌC DATA
    DATASET_PATH = "/content/master_dataset_for_cnn_gru.csv"
    df = pd.read_csv(DATASET_PATH)
    
    if 'target_label' not in df.columns:
        label_col = 'label' if 'label' in df.columns else df.columns[-1]
    else:
        label_col = 'target_label'

    X_raw = df.drop(columns=[label_col]).values
    y_raw = df[label_col].values

    # CHUẨN HÓA & LƯU SCALER 
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    joblib.dump(scaler, 'sdn_scaler.pkl')
    print("✅ Đã xuất file cấu hình chuẩn hóa: sdn_scaler.pkl")

    # TẠO SEQUENCE & SPLIT DATA
    X_seq, y_seq = create_safe_sequences(X_scaled, y_raw, SEQ_LEN)
    X_train, X_test, y_train, y_test = train_test_split(X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq)
    
    train_loader = DataLoader(SDNFlowDataset(X_train, y_train), batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(SDNFlowDataset(X_test, y_test), batch_size=BATCH_SIZE, shuffle=False)

    # TÍNH TRỌNG SỐ LỚP 
    classes = np.unique(y_train)
    raw_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    clipped_weights = np.clip(raw_weights, a_min=None, a_max=10.0) # Khóa trần trọng số
    tensor_weights = torch.FloatTensor(clipped_weights).to(DEVICE)
    print(f"⚖️ Trọng số phạt đã làm mềm: {clipped_weights}")

    # KHỞI TẠO MÔ HÌNH VÀ CÁC CÔNG CỤ TỐI ƯU HÓA TẦNG CAO
    model = DDos_CNN_GRU().to(DEVICE)
    
    # [KỸ THUẬT 1] Label Smoothing = 0.1 (Chữa bệnh hoang tưởng, tự tin thái quá)
    criterion = nn.CrossEntropyLoss(weight=tensor_weights, label_smoothing=0.1)
    
    # L2 Regularization (weight_decay) giúp mài dũa trọng số gọn gàng
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5) 
    
    # [KỸ THUẬT 2] OneCycleLR: Lên ga mạnh ở giữa, rà phanh mượt về cuối
    scheduler = optim.lr_scheduler.OneCycleLR(
        optimizer, 
        max_lr=0.005, # Tốc độ tối đa khi "thốc ga"
        steps_per_epoch=len(train_loader), 
        epochs=EPOCHS
    )

    # HUẤN LUYỆN
    train_losses, test_accs = [], []
    best_acc = 0.0
    patience = 10
    trigger_times = 0

    for epoch in range(EPOCHS):
        model.train()
        total_loss, correct, total = 0, 0, 0
        start_time = time.time()
        
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(DEVICE), batch_y.to(DEVICE)
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            
            # [KỸ THUẬT 3] Gradient Clipping (Chống bùng nổ đạo hàm do nhiễu luồng)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            
            optimizer.step()
            scheduler.step() # OneCycleLR bắt buộc phải chạy theo TỪNG BATCH
            
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += batch_y.size(0)
            correct += predicted.eq(batch_y).sum().item()
            
        train_acc = 100. * correct / total
        
        # ĐÁNH GIÁ TRÊN TẬP TEST
        model.eval()
        test_correct, test_total = 0, 0
        with torch.no_grad():
            for batch_X, batch_y in test_loader:
                outputs = model(batch_X.to(DEVICE))
                _, predicted = outputs.max(1)
                test_total += batch_y.size(0)
                test_correct += predicted.eq(batch_y.to(DEVICE)).sum().item()
        
        test_acc = 100. * test_correct / test_total
        print(f"Epoch [{epoch+1}/{EPOCHS}] | Loss: {total_loss/len(train_loader):.4f} | Train Acc: {train_acc:.2f}% | Test Acc: {test_acc:.2f}% | Time: {time.time()-start_time:.1f}s")
        
        # Early Stopping & Save Best Model
        if test_acc > best_acc:
            best_acc = test_acc
            torch.save(model.state_dict(), 'sdn_model_cnn_gru.pth')
            print(f"⭐ Đã lưu mô hình tốt nhất với Accuracy: {best_acc:.2f}%")
            trigger_times = 0
        else:
            trigger_times += 1
            if trigger_times >= patience:
                print(f"Early stopping tại epoch {epoch+1}")
                break

    # ĐÁNH GIÁ (TESTING) VÀ VẼ BIỂU ĐỒ
    model.eval()
    all_preds, all_targets = [], []
    with torch.no_grad():
        for batch_X, batch_y in test_loader:
            outputs = model(batch_X.to(DEVICE))
            _, preds = outputs.max(1)
            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(batch_y.numpy())

    print("\n" + "="*50)
    print(" 📊 BÁO CÁO ĐỘ CHÍNH XÁC (CLASSIFICATION REPORT)")
    print("="*50)
    target_names = [LABEL_NAMES[i] for i in range(NUM_CLASSES)]
    print(classification_report(all_targets, all_preds, target_names=target_names, zero_division=0))

    # VẼ MA TRẬN NHẦM LẪN (Confusion Matrix)
    cm = confusion_matrix(all_targets, all_preds)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
    plt.ylabel('Thực tế (Actual)')
    plt.xlabel('Dự đoán của AI (Predicted)')
    plt.title('Ma Trận Nhầm Lẫn - Đánh giá hiệu năng AI')
    plt.savefig('confusion_matrix.png')
    print("✅ Đã lưu biểu đồ: confusion_matrix.png")'''
'''v1: 1. Kỹ thuật "Cắt xén Gradient" (Gradient Clipping) - Nên dùngVấn đề: Mạng GRU/RNN khi xử lý chuỗi thời gian rất dễ bị một bệnh gọi là "Bùng nổ Gradient" (Exploding Gradients). Đôi khi có một luồng dữ liệu nhiễu đi vào, đạo hàm tính ra quá lớn, làm trọng số bị văng xa khỏi quỹ đạo.Giải pháp: Thêm chốt chặn an toàn. Trước khi optimizer.step(), ta chặn không cho bất kỳ lực cập nhật nào vượt quá một ngưỡng nhất định (ví dụ: max_norm=1.0).Cách thêm: Chỉ cần 1 dòng code: torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)2. Kỹ thuật "Làm mềm nhãn" (Label Smoothing) - Trị bệnh hoang tưởngVấn đề: Mạng phân loại (Cross Entropy) thường quá tự tin. Khi nó đoán một luồng là SYN Flood, nó ép xác suất phải là 100%, 0% cho các nhãn còn lại. Sự tự tin thái quá này làm AI dễ bị lừa (Overconfidence) và dẫn đến bệnh "Paranoia" với Slowloris như ta thấy ở trên.Giải pháp: Bắt AI phải chừa lại một đường lui. Thay vì ép nhãn đúng là $1.0$ (100%), ta ép nó học nhãn đúng là $0.9$ (90%), và chia đều $10\%$ sự nghi ngờ cho các nhãn còn lại.Cách thêm: criterion = nn.CrossEntropyLoss(weight=tensor_weights, label_smoothing=0.1)3. Bộ lập lịch xịn nhất thế giới hiện tại: OneCycleLRVấn đề: ReduceLROnPlateau khá thụ động (chỉ chờ lỗi không giảm mới đạp phanh).Giải pháp: Sử dụng OneCycleLR. Bộ lập lịch này hoạt động như một tay đua xe F1 chuyên nghiệp: Khởi đầu bằng việc đạp thốc ga (tăng vọt Learning Rate) để vượt qua các vũng bùn (local minima), sau đó từ từ thả ga và rà phanh cực mượt về cuối. Nó giúp AI khái quát hóa cực tốt.'''
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
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time

import torch.nn.functional as F
# IMPORT CÁC MÔ HÌNH MỚI TỪ CONFIG
from config import Anomaly_Autoencoder, DDos_CNN_GRU_Attention, NUM_FEATURES, SEQ_LEN, LABEL_NAMES, NUM_CLASSES 
am=10.0
# 1. THIẾT LẬP THÔNG SỐ
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

class FocalLoss(nn.Module):
    def __init__(self, weight=None, gamma=2.0):
        super(FocalLoss, self).__init__()
        self.weight = weight
        self.gamma = gamma

    def forward(self, inputs, targets):
        ce_loss = F.cross_entropy(inputs, targets, weight=self.weight, reduction='none')
        pt = torch.exp(-ce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * ce_loss
        return focal_loss.mean()

BATCH_SIZE = 512
EPOCHS_AE = 15      # Epoch cho Autoencoder
EPOCHS_CLS = 30     # Epoch cho Classifier (Phân loại)

print(f"🚀 Đang train trên thiết bị: {DEVICE}")

# 2. DATASET VÀ CỬA SỔ TRƯỢT AN TOÀN
class SDNFlowDataset(Dataset):
    def __init__(self, sequences, labels):
        self.sequences = torch.FloatTensor(sequences)
        self.labels = torch.LongTensor(labels)
    def __len__(self): return len(self.labels)
    def __getitem__(self, idx): return self.sequences[idx], self.labels[idx]

def create_safe_sequences(features, labels, seq_len):
    """Cửa sổ trượt CHỈ GỘP KHI ĐỒNG NHẤT NHÃN (Chống Data Leakage)"""
    print(f"⏳ Đang tạo chuỗi Time-Series (Seq_len = {seq_len})...")
    X, y = [], []
    stride = seq_len 
    
    for i in range(0, len(features) - seq_len, stride):
        window_labels = labels[i : i + seq_len]
        if np.all(window_labels == window_labels[0]):
            X.append(features[i : i + seq_len])
            y.append(window_labels[-1])
            
    return np.array(X), np.array(y)


# 3. MẠCH CHÍNH (TWO-PHASE TRAINING)
if __name__ == "__main__":
    # ==========================================
    # CHUẨN BỊ DỮ LIỆU CHUNG
    # ==========================================
    #DATASET_PATH = "/content/master_dataset_for_cnn_gru.csv"
    DATASET_PATH = "/content/drive/MyDrive/SDN_Project/master_dataset_for_cnn_gru.csv"
    df = pd.read_csv(DATASET_PATH)
    
    label_col = 'target_label' if 'target_label' in df.columns else df.columns[-1]

    X_raw = df.drop(columns=[label_col]).values
    y_raw = df[label_col].values

    # CHUẨN HÓA & LƯU SCALER 
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    joblib.dump(scaler, 'sdn_scaler.pkl')
    print("✅ Đã xuất file cấu hình chuẩn hóa: sdn_scaler.pkl\n")

    # TẠO SEQUENCE CHUNG
    X_seq, y_seq = create_safe_sequences(X_scaled, y_raw, SEQ_LEN)
    
    # ==========================================
    # GIAI ĐOẠN 1: HUẤN LUYỆN AUTOENCODER (BẮT ZERO-DAY)
    # ==========================================
    print("="*60)
    print(" 🛡️ GIAI ĐOẠN 1: HUẤN LUYỆN AUTOENCODER (DỮ LIỆU SẠCH)")
    print("="*60)
    
    # Chỉ lấy dữ liệu Benign (Nhãn 0) để dạy Autoencoder
    benign_idx = (y_seq == 0)
    X_benign = X_seq[benign_idx]
    
    # Chia Train/Test cho Autoencoder
    X_train_ae, X_test_ae = train_test_split(X_benign, test_size=0.2, random_state=42)
    ae_loader = DataLoader(TensorDataset(torch.FloatTensor(X_train_ae)), batch_size=BATCH_SIZE, shuffle=True)
    
    ae_model = Anomaly_Autoencoder().to(DEVICE)
    ae_criterion = nn.MSELoss() # Dùng sai số bình phương (Reconstruction Error)
    ae_optimizer = optim.Adam(ae_model.parameters(), lr=0.001)
    
    for epoch in range(EPOCHS_AE):
        ae_model.train()
        total_loss = 0
        for batch_X in ae_loader:
            batch_X = batch_X[0].to(DEVICE) # TensorDataset trả về tuple
            ae_optimizer.zero_grad()
            reconstructed = ae_model(batch_X)
            loss = ae_criterion(reconstructed, batch_X)
            loss.backward()
            ae_optimizer.step()
            total_loss += loss.item()
        print(f"AE Epoch [{epoch+1}/{EPOCHS_AE}] | MSE Loss: {total_loss/len(ae_loader):.4f}")
    
    # TÍNH TOÁN NGƯỠNG DỊ THƯỜNG (THRESHOLD)
    ae_model.eval()
    with torch.no_grad():
        X_ae_tensor = torch.FloatTensor(X_train_ae).to(DEVICE)
        reconstructed_train = ae_model(X_ae_tensor)
        # Tính MSE cho từng chuỗi
        mse_errors = torch.mean((X_ae_tensor - reconstructed_train)**2, dim=(1,2)).cpu().numpy()
        # Lấy mốc 95% làm ngưỡng: Bất cứ chuỗi nào có lỗi tái tạo cao hơn mốc này sẽ bị coi là Zero-Day
        anomaly_threshold = np.percentile(mse_errors, 95)
    
    joblib.dump(anomaly_threshold, 'ae_threshold.pkl')
    torch.save(ae_model.state_dict(), 'sdn_autoencoder.pth')
    print(f"✅ Đã lưu Autoencoder. Ngưỡng phát hiện Zero-Day (Threshold): {anomaly_threshold:.4f}\n")


    # ==========================================
    # GIAI ĐOẠN 2: HUẤN LUYỆN CLASSIFIER (CNN-GRU-ATTENTION)
    # ==========================================
    print("="*60)
    print(" 👁️ GIAI ĐOẠN 2: HUẤN LUYỆN CNN-GRU-ATTENTION")
    print("="*60)
    
    # Chia Train/Test trên TOÀN BỘ dữ liệu (5 nhãn)
    X_train, X_test, y_train, y_test = train_test_split(X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq)
    train_loader = DataLoader(SDNFlowDataset(X_train, y_train), batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(SDNFlowDataset(X_test, y_test), batch_size=BATCH_SIZE, shuffle=False)

    # TÍNH TRỌNG SỐ LỚP 
    classes = np.unique(y_train)
    raw_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    clipped_weights = np.clip(raw_weights, a_min=None, a_max=7.5) 
    tensor_weights = torch.FloatTensor(clipped_weights).to(DEVICE)

    # KHỞI TẠO MÔ HÌNH ATTENTION
    model = DDos_CNN_GRU_Attention().to(DEVICE)
    criterion = nn.CrossEntropyLoss(weight=tensor_weights)
    #criterion = nn.CrossEntropyLoss(weight=tensor_weights, label_smoothing=0.1)
    #criterion = FocalLoss(weight=tensor_weights, gamma=2.0)
    optimizer = optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-5) 
    scheduler = optim.lr_scheduler.OneCycleLR(optimizer, max_lr=0.005, steps_per_epoch=len(train_loader), epochs=EPOCHS_CLS)

    best_acc = 0.0
    patience = 12
    trigger_times = 0

    for epoch in range(EPOCHS_CLS):
        model.train()
        total_loss, correct, total = 0, 0, 0
        start_time = time.time()
        
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(DEVICE), batch_y.to(DEVICE)
            optimizer.zero_grad()
            
            # CHÚ Ý: Mô hình mới trả về 2 output (Kết quả và Trọng số Attention)
            outputs, _ = model(batch_X) 
            
            loss = criterion(outputs, batch_y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()
            
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += batch_y.size(0)
            correct += predicted.eq(batch_y).sum().item()
            
        train_acc = 100. * correct / total
        
        # ĐÁNH GIÁ TRÊN TẬP TEST
        model.eval()
        test_correct, test_total = 0, 0
        with torch.no_grad():
            for batch_X, batch_y in test_loader:
                outputs, _ = model(batch_X.to(DEVICE))
                _, predicted = outputs.max(1)
                test_total += batch_y.size(0)
                test_correct += predicted.eq(batch_y.to(DEVICE)).sum().item()
        
        test_acc = 100. * test_correct / test_total
        print(f"Epoch [{epoch+1}/{EPOCHS_CLS}] | Loss: {total_loss/len(train_loader):.4f} | Train Acc: {train_acc:.2f}% | Test Acc: {test_acc:.2f}% | Time: {time.time()-start_time:.1f}s")
        
        if test_acc > best_acc:
            best_acc = test_acc
            torch.save(model.state_dict(), 'sdn_model_cnn_gru_attn.pth')
            print(f"⭐ Đã lưu mô hình tốt nhất với Accuracy: {best_acc:.2f}%")
            trigger_times = 0
        else:
            trigger_times += 1
            if trigger_times >= patience:
                print(f"Early stopping tại epoch {epoch+1}")
                break

    # ĐÁNH GIÁ (TESTING) VÀ VẼ BIỂU ĐỒ
    model.eval()
    all_preds, all_targets = [], []
    with torch.no_grad():
        for batch_X, batch_y in test_loader:
            outputs, _ = model(batch_X.to(DEVICE))
            _, preds = outputs.max(1)
            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(batch_y.numpy())

    print("\n" + "="*50)
    print(" 📊 BÁO CÁO ĐỘ CHÍNH XÁC (CLASSIFICATION REPORT)")
    print("="*50)
    target_names = [LABEL_NAMES[i] for i in range(NUM_CLASSES)]
    print(classification_report(all_targets, all_preds, target_names=target_names, zero_division=0))

    cm = confusion_matrix(all_targets, all_preds)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
    plt.ylabel('Thực tế (Actual)')
    plt.xlabel('Dự đoán của AI (Predicted)')
    plt.title('Ma Trận Nhầm Lẫn - Đánh giá hiệu năng AI')
    plt.savefig('confusion_matrix.png')
    print("✅ Đã lưu biểu đồ: confusion_matrix.png")