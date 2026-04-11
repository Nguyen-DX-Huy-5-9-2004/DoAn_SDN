# Tên file: train_colab.py
import pandas as pd
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

from config import DDos_CNN_GRU, NUM_FEATURES, SEQ_LEN, LABEL_NAMES, NUM_CLASSES # Import từ file cấu hình

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
    """Cửa sổ trượt CHỈ GỘP KHI ĐỒNG NHẤT NHÃN (Tránh nhiễu chéo)"""
    print(f"⏳ Đang tạo chuỗi Time-Series (Seq_len = {seq_len})...")
    X, y = [], []
    stride = seq_len
    
    for i in range(0, len(features) - seq_len, stride):
        window_labels = labels[i : i + seq_len]
        # Ký thuật cốt lõi: Chỉ gộp nếu toàn bộ 10 dòng có chung 1 nhãn
        if np.all(window_labels == window_labels[0]):
            X.append(features[i : i + seq_len])
            y.append(window_labels[-1])
            
    return np.array(X), np.array(y)

# 3. MẠCH CHÍNH
if __name__ == "__main__":
    # ĐỌC DATA
    #DATASET_PATH = "/home/tgf/Documents/DoAn_SDN/dataset/master_dataset_for_cnn_gru.csv"
    DATASET_PATH = "/content/master_dataset_for_cnn_gru.csv"
    df = pd.read_csv(DATASET_PATH)
    
    # Loại bỏ các cột không phải đặc trưng (nếu có)
    # Giả sử file CSV có cột 'target_label' là nhãn
    if 'target_label' not in df.columns:
        # Nếu tên cột nhãn khác, hãy đổi ở đây. Ví dụ: 'label'
        label_col = 'label' if 'label' in df.columns else df.columns[-1]
    else:
        label_col = 'target_label'

    X_raw = df.drop(columns=[label_col]).values
    y_raw = df[label_col].values

    # CHUẨN HÓA & LƯU SCALER (Cực kỳ quan trọng để run trên máy thật)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    joblib.dump(scaler, 'sdn_scaler.pkl')
    print("✅ Đã xuất file cấu hình chuẩn hóa: sdn_scaler.pkl")

    # TẠO SEQUENCE & SPLIT DATA (80% Train, 20% Test)
    X_seq, y_seq = create_safe_sequences(X_scaled, y_raw, SEQ_LEN)
    X_train, X_test, y_train, y_test = train_test_split(X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq)
    
    train_loader = DataLoader(SDNFlowDataset(X_train, y_train), batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(SDNFlowDataset(X_test, y_test), batch_size=BATCH_SIZE, shuffle=False)

    # TÍNH TRỌNG SỐ LỚP (Bảo vệ tuyệt đối Slowloris)
    classes = np.unique(y_train)
    class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    tensor_weights = torch.FloatTensor(class_weights).to(DEVICE)
    print(f"⚖️ Trọng số phạt tự động: {class_weights}")

    # KHỞI TẠO MÔ HÌNH
    model = DDos_CNN_GRU().to(DEVICE)
    criterion = nn.CrossEntropyLoss(weight=tensor_weights)
    optimizer = optim.Adam(model.parameters(), lr=0.001)

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
            optimizer.step()
            
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += batch_y.size(0)
            correct += predicted.eq(batch_y).sum().item()
            
        train_acc = 100. * correct / total
        
        # ĐÁNH GIÁ NHANH TRÊN TẬP TEST SAU MỖI EPOCH
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
    print(classification_report(all_targets, all_preds, target_names=target_names))

    # VẼ MA TRẬN NHẦM LẪN (Confusion Matrix)
    cm = confusion_matrix(all_targets, all_preds)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
    plt.ylabel('Thực tế (Actual)')
    plt.xlabel('Dự đoán của AI (Predicted)')
    plt.title('Ma Trận Nhầm Lẫn - Đánh giá hiệu năng AI')
    plt.savefig('confusion_matrix.png')
    print("✅ Đã lưu biểu đồ: confusion_matrix.png")