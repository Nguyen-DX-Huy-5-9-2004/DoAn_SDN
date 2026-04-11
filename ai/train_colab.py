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
import os
import random

# IMPORT CÁC MÔ HÌNH MỚI TỪ CONFIG
from config import Anomaly_Autoencoder, DDos_CNN_GRU_Attention, NUM_FEATURES, SEQ_LEN, LABEL_NAMES, NUM_CLASSES 

# --- ĐÓNG BĂNG SỰ NGẪU NHIÊN ĐỂ KẾT QUẢ KHÔNG ĐỔI ---
def seed_everything(seed=42):
    random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True 
    torch.backends.cudnn.benchmark = False

seed_everything(42)

# 1. THIẾT LẬP THÔNG SỐ
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BATCH_SIZE = 512
EPOCHS_AE = 15      
EPOCHS_CLS = 30     

print(f"🚀 Đang train trên thiết bị: {DEVICE}")

# 2. DATASET VÀ CỬA SỔ TRƯỢT AN TOÀN
class SDNFlowDataset(Dataset):
    def __init__(self, sequences, labels):
        self.sequences = torch.FloatTensor(sequences)
        self.labels = torch.LongTensor(labels)
    def __len__(self): return len(self.labels)
    def __getitem__(self, idx): return self.sequences[idx], self.labels[idx]

def create_safe_sequences(features, labels, seq_len):
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
    # ĐỌC DATA - Tự động bỏ qua các dòng lỗi (on_bad_lines='skip')
    DATASET_PATH = "/content/drive/MyDrive/SDN_Project/master_dataset_for_cnn_gru.csv"
    df = pd.read_csv(DATASET_PATH, on_bad_lines='skip')
    
    label_col = 'target_label' if 'target_label' in df.columns else df.columns[-1]
    X_raw = df.drop(columns=[label_col]).values
    y_raw = df[label_col].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    joblib.dump(scaler, 'sdn_scaler.pkl')

    X_seq, y_seq = create_safe_sequences(X_scaled, y_raw, SEQ_LEN)
    
    # ==========================================
    # GIAI ĐOẠN 1: HUẤN LUYỆN AUTOENCODER (BẮT ZERO-DAY)
    # ==========================================
    print("="*60)
    print(" 🛡️ GIAI ĐOẠN 1: HUẤN LUYỆN AUTOENCODER (DỮ LIỆU SẠCH)")
    print("="*60)
    
    benign_idx = (y_seq == 0)
    X_benign = X_seq[benign_idx]
    
    X_train_ae, X_test_ae = train_test_split(X_benign, test_size=0.2, random_state=42)
    ae_loader = DataLoader(TensorDataset(torch.FloatTensor(X_train_ae)), batch_size=BATCH_SIZE, shuffle=True)
    
    ae_model = Anomaly_Autoencoder().to(DEVICE)
    ae_criterion = nn.MSELoss() 
    ae_optimizer = optim.Adam(ae_model.parameters(), lr=0.001)
    
    for epoch in range(EPOCHS_AE):
        ae_model.train()
        total_loss = 0
        for batch_X in ae_loader:
            batch_X = batch_X[0].to(DEVICE) 
            ae_optimizer.zero_grad()
            reconstructed = ae_model(batch_X)
            loss = ae_criterion(reconstructed, batch_X)
            loss.backward()
            ae_optimizer.step()
            total_loss += loss.item()
        print(f"AE Epoch [{epoch+1}/{EPOCHS_AE}] | MSE Loss: {total_loss/len(ae_loader):.4f}")
    
    ae_model.eval()
    with torch.no_grad():
        X_ae_tensor = torch.FloatTensor(X_train_ae).to(DEVICE)
        reconstructed_train = ae_model(X_ae_tensor)
        mse_errors = torch.mean((X_ae_tensor - reconstructed_train)**2, dim=(1,2)).cpu().numpy()
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
    
    X_train, X_test, y_train, y_test = train_test_split(X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq)
    train_loader = DataLoader(SDNFlowDataset(X_train, y_train), batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(SDNFlowDataset(X_test, y_test), batch_size=BATCH_SIZE, shuffle=False)

    classes = np.unique(y_train)
    raw_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    # Điểm neo vàng: a_max = 7.5
    clipped_weights = np.clip(raw_weights, a_min=None, a_max=7.5) 
    tensor_weights = torch.FloatTensor(clipped_weights).to(DEVICE)

    model = DDos_CNN_GRU_Attention().to(DEVICE)
    # Ranh giới sắc nét: Không dùng label_smoothing
    criterion = nn.CrossEntropyLoss(weight=tensor_weights)
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