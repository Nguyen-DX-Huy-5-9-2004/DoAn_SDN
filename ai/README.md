# SDN-IDS AI MODULE DOCUMENTATION

## 1. Overview
The `ai/` directory contains the core intelligence of the SDN-IDS system. It utilizes a two-stage defense mechanism:
1.  **Stage 1 (Anomaly Detection)**: An Autoencoder-based model that identifies Zero-Day attacks and traffic variants.
2.  **Stage 2 (Classification)**: A Deep Learning model (CNN-GRU-Attention) that classifies known DDoS attack types.

## 2. File Descriptions

### `config.py` (The Brain)
- **Purpose**: Centralized configuration for model architectures, hyperparameters, and labels.
- **Key Components**:
    - `Anomaly_Autoencoder`: Neural network for reconstruction-based anomaly detection.
    - `DDos_CNN_GRU_Attention`: Main classifier combining spatial (CNN) and temporal (GRU) feature extraction with an Attention mechanism.
    - `AIModelManager`: Static helper to load the entire pipeline (scaler, models, thresholds) into memory.
    - `SDN_XAI_Explainer`: Explainable AI module that identifies which network features contributed most to a specific detection.

### `run_onos.py` (Real-time IDS Engine)
- **Purpose**: The main execution loop that connects the Zeek traffic stream to the AI models and the ONOS controller.
- **Key Features**:
    - **Adaptive Threshold**: Automatically adjusts the anomaly detection threshold based on real-time network conditions (Concept Drift protection).
    - **SDNController**: Decoupled module to push Flow Rules (Block, Rate Limit, Redirect) to ONOS.
    - **Anti-Spoofing**: Buffering logic to prevent memory exhaustion from spoofed IP attacks.
- **Input**: `zeek_stream.json` (Named Pipe).
- **Output**: Flow Rules pushed to ONOS via REST API.

### `train_colab.py` (Training Pipeline)
- **Purpose**: End-to-end script for training both the Autoencoder and the Classifier.
- **Improvements**:
    - **Data Augmentation**: Adds Gaussian noise to training samples for better robustness.
    - **Early Stopping**: Prevents overfitting by monitoring validation accuracy.
    - **Class Balancing**: Uses weighted loss functions to handle imbalanced datasets.
- **Output**: `sdn_model_cnn_gru_attn.pth`, `sdn_autoencoder.pth`, `sdn_scaler.pkl`.

### `ai_monitor.py` (Performance Dashboard)
- **Purpose**: A real-time terminal dashboard to monitor the IDS system's health.
- **Metrics**: Displays MSE loss distribution, active IP tracking, latency, and mitigation counts.

### `benchmark_report.py`
- **Purpose**: Generates a comprehensive performance report (Latency, Throughput, Precision/Recall) and saves a visualization dashboard (`ai_performance_dashboard.png`).

### `tests_class2.py`
- **Purpose**: Unit and integration tests for the AI modules to ensure > 90% code coverage and adherence to latency requirements (< 100ms).

## 3. How to Integrate
1.  **Train**: Run `train_colab.py` to generate the `.pth` and `.pkl` files.
2.  **Deploy**: Ensure the trained files are in the `ai/` folder.
3.  **Run**: Start `run_onos.py`. It will automatically use the `AIModelManager` to load all necessary components.
4.  **Monitor**: Open a separate terminal and run `ai_monitor.py` to watch the system in real-time.
