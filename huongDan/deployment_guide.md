# HƯỚNG DẪN TRIỂN KHAI VÀ GIÁM SÁT HỆ THỐNG IDS LỚP 2 (PHASE 2)

## 1. Cấu trúc Hệ thống (Architecture)
Hệ thống sử dụng mô hình CNN + GRU + Attention để phân loại lưu lượng mạng:
- **Feature Extractor**: Sử dụng CNN 1D để trích xuất đặc trưng không gian và GRU 2 lớp để học hành vi theo chuỗi thời gian (Sequence of 10 flows).
- **Attention Layer**: Tập trung vào các flow quan trọng nhất trong chuỗi để đưa ra quyết định.
- **Classifier**: Mạng Fully Connected 2 lớp để phân loại 5 nhãn (Normal, UDP, SYN, HTTP, Slowloris).

## 2. Yêu cầu Hiệu suất (Quality Standards)
- **Độ chính xác (Accuracy)**: > 95% cho phân loại Normal vs Attack.
- **Độ trễ (Latency)**: < 100ms cho mỗi dự đoán (Trung bình ~5-10ms trên CPU/GPU).
- **Thông lượng (Throughput)**: > 1000 chuỗi flow/giây.

## 3. Quy trình Triển khai (Deployment Guide)
### Bước 1: Thu thập dữ liệu
Chạy bộ sinh dataset 5 nhãn để lấy dữ liệu huấn luyện:
```bash
sudo python3 thuThapData/auto_dataset_generator.py
```

### Bước 2: Huấn luyện mô hình
Upload `master_dataset_v5.csv` lên Google Colab và chạy:
```python
python3 ai/train_colab.py
```
Kết quả sẽ xuất ra các file: `sdn_model_cnn_gru_attn.pth`, `sdn_autoencoder.pth`, `sdn_scaler.pkl`, `ae_threshold.pkl`.

### Bước 3: Kiểm định hiệu năng
Chạy script benchmark để kiểm tra Latency, Throughput và xuất báo cáo Visualization:
```bash
python3 ai/benchmark_report.py
```

### Bước 4: Chạy IDS trên ONOS
```bash
python3 ai/run_onos.py
```

## 4. Cơ chế Giám sát (Monitoring)
Hệ thống tích hợp **Explainable AI (XAI)** để giải thích lý do chặn:
- Khi một IP bị chặn, module XAI sẽ phân tích flow quan trọng nhất trong chuỗi và in ra lý do (ví dụ: "Băng thông tiêu thụ lớn", "is_weird=1").
- Sử dụng file `confusion_matrix.png` và báo cáo từ `benchmark_report.py` để theo dõi sự ổn định của mô hình trong quá trình vận hành.

## 5. Xử lý lỗi (Troubleshooting)
- Nếu Latency > 100ms: Kiểm tra tải CPU hoặc chuyển sang sử dụng GPU (CUDA).
- Nếu Accuracy < 95%: Thực hiện thu thập thêm dữ liệu (Data Augmentation) hoặc tinh chỉnh lại bộ lọc trùng lặp trong `auto_dataset_generator.py`.
