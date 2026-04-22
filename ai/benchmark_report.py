import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from torch.utils.data import DataLoader, TensorDataset
import os
import sys

# Import components from config
from config import DDos_CNN_GRU_Attention, NUM_FEATURES, SEQ_LEN, LABEL_NAMES, NUM_CLASSES

def benchmark_model(model_path, dataset_path):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Benchmarking model on device: {device}")

    # 1. Load Model
    model = DDos_CNN_GRU_Attention().to(device)
    try:
        model.load_state_dict(torch.load(model_path, map_location=device))
        model.eval()
        print(f"[+] Loaded model from {model_path}")
    except Exception as e:
        print(f"[-] Error loading model: {e}")
        return

    # 2. Load and Preprocess Data
    print(f"[*] Loading dataset from {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        print(f"[-] Error loading dataset: {e}")
        return

    # Basic preprocessing (same as training)
    df.dropna(inplace=True)
    label_col = 'target_label'
    X = df.drop(columns=[label_col]).values
    y = df[label_col].values

    # Create sequences (simplified for benchmark)
    def create_sequences(X, y, seq_len):
        X_seq, y_seq = [], []
        for i in range(len(X) - seq_len):
            X_seq.append(X[i:i+seq_len])
            y_seq.append(y[i+seq_len-1])
        return np.array(X_seq), np.array(y_seq)

    print("[*] Creating sequences...")
    X_seq, y_seq = create_sequences(X, y, SEQ_LEN)
    
    # Use a subset for faster benchmark if needed
    if len(X_seq) > 50000:
        indices = np.random.choice(len(X_seq), 50000, replace=False)
        X_seq, y_seq = X_seq[indices], y_seq[indices]

    X_tensor = torch.FloatTensor(X_seq).to(device)
    y_tensor = torch.LongTensor(y_seq).to(device)
    
    dataset = TensorDataset(X_tensor, y_tensor)
    loader = DataLoader(dataset, batch_size=64, shuffle=False)

    # 3. Performance Benchmark (Latency & Throughput)
    print("\n" + "="*50)
    print("🚀 PERFORMANCE BENCHMARK")
    print("="*50)
    
    start_time = time.time()
    all_preds = []
    all_probs = []
    
    # Warm up
    _ = model(X_tensor[:1])
    
    num_samples = len(X_tensor)
    latencies = []
    
    with torch.no_grad():
        for i in range(min(100, num_samples)):
            sample = X_tensor[i:i+1]
            s = time.time()
            model(sample)
            latencies.append((time.time() - s) * 1000) # ms
            
        # Bulk prediction for throughput
        start_bulk = time.time()
        for batch_X, _ in loader:
            out, _ = model(batch_X)
            probs = torch.softmax(out, dim=1)
            all_probs.extend(probs.cpu().numpy())
            all_preds.extend(torch.argmax(out, dim=1).cpu().numpy())
        end_bulk = time.time()

    avg_latency = np.mean(latencies)
    throughput = num_samples / (end_bulk - start_bulk)
    
    print(f"[*] Average Latency per prediction: {avg_latency:.2f} ms (Goal: < 100ms)")
    print(f"[*] Throughput: {throughput:.2f} sequences/sec (Goal: > 1000/s)")
    
    # 4. Quality Metrics (Accuracy, Precision, Recall, F1)
    print("\n" + "="*50)
    print("📈 QUALITY METRICS")
    print("="*50)
    
    report = classification_report(y_seq, all_preds, target_names=[LABEL_NAMES[i] for i in range(NUM_CLASSES)])
    print(report)
    
    # 5. Visualization (Confusion Matrix & ROC)
    print("\n[*] Generating Visualization Dashboard...")
    plt.figure(figsize=(20, 8))
    
    # Subplot 1: Confusion Matrix
    plt.subplot(1, 2, 1)
    cm = confusion_matrix(y_seq, all_preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=[LABEL_NAMES[i] for i in range(NUM_CLASSES)],
                yticklabels=[LABEL_NAMES[i] for i in range(NUM_CLASSES)])
    plt.title('Confusion Matrix - SDN IDS Class 2')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')

    # Subplot 2: ROC Curves
    plt.subplot(1, 2, 2)
    all_probs = np.array(all_probs)
    for i in range(NUM_CLASSES):
        fpr, tpr, _ = roc_curve(y_seq == i, all_probs[:, i])
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, lw=2, label=f'{LABEL_NAMES[i]} (AUC = {roc_auc:.2f})')
    
    plt.plot([0, 1], [0, 1], 'k--', lw=2)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Multi-class ROC Curves')
    plt.legend(loc="lower right")

    plt.tight_layout()
    plot_path = "ai_performance_dashboard.png"
    plt.savefig(plot_path)
    print(f"[+] Dashboard saved to {plot_path}")

if __name__ == "__main__":
    # Check for model and data
    MODEL_PATH = "sdn_model_cnn_gru_attn.pth"
    DATASET_PATH = "master_dataset_v5.csv"
    
    if not os.path.exists(MODEL_PATH):
        # Create a dummy model for demonstration if file doesn't exist
        print(f"[!] Model {MODEL_PATH} not found. Running with a dummy model for structure validation.")
        model = DDos_CNN_GRU_Attention()
        torch.save(model.state_dict(), MODEL_PATH)
        
    if not os.path.exists(DATASET_PATH):
        # Create dummy data for demonstration
        print(f"[!] Dataset {DATASET_PATH} not found. Creating dummy data.")
        data = np.random.rand(1000, 13)
        labels = np.random.randint(0, 5, 1000)
        df = pd.DataFrame(data, columns=[f"f{i}" for i in range(13)])
        df['target_label'] = labels
        df.to_csv(DATASET_PATH, index=False)

    benchmark_model(MODEL_PATH, DATASET_PATH)
