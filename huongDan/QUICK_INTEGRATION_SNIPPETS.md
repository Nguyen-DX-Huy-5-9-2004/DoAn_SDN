# QUICK INTEGRATION SNIPPETS
# Sao chép các đoạn code này vào files hiện tại

# =========================================================================
# 1. ai/ai_monitor.py - THÊM IMPORT & INITIALIZE
# =========================================================================

# ===== Thêm vào đầu file =====
"""
# Existing imports...
import logging
from ids_onos_integration import process_ai_prediction, initialize_ids, get_ids_status
"""

# ===== Thêm hàm initialize (nếu chưa có) =====
"""
def init_ids_engine():
    '''Khởi tạo IDS Engine với ONOS'''
    global ids_engine
    try:
        ids_engine = initialize_ids(use_onos=True)
        logger.info("[Monitor] IDS Engine initialized with ONOS")
    except Exception as e:
        logger.error(f"[Monitor] Failed to init IDS: {e}")
        ids_engine = initialize_ids(use_onos=False)  # Fallback OVS
"""

# ===== Thêm vào function xử lý dự đoán =====
"""
def process_predictions_v2(flows, ae_scores, cls_predictions):
    '''
    Process AI predictions và thực thi IDS actions
    
    flows: [(src_ip, dst_ip, protocol, ...), ...]
    ae_scores: [reconstruction_error1, error2, ...]
    cls_predictions: [(label, confidence), ...]
    '''
    results = []
    
    for flow, ae_score, (pred_label, confidence) in zip(flows, ae_scores, cls_predictions):
        src_ip = flow[0]  # Giả sử src_ip ở index 0
        
        # ===== GỌI IDS ENGINE =====
        action, reason = process_ai_prediction(
            src_ip=src_ip,
            predicted_label=pred_label,
            confidence=confidence
        )
        
        # ===== XỬ LÝ ACTION =====
        if action == "BLOCK":
            logger.warning(f"🛡️  BLOCKED: {src_ip} - {reason}")
            results.append({
                "src_ip": src_ip,
                "action": "BLOCK",
                "reason": reason,
                "timestamp": time.time()
            })
        elif action == "MONITOR":
            logger.info(f"📊 MONITORING: {src_ip} - {reason}")
            results.append({
                "src_ip": src_ip,
                "action": "MONITOR",
                "reason": reason,
                "timestamp": time.time()
            })
        else:  # PASS
            logger.debug(f"✓ PASS: {src_ip}")
            results.append({
                "src_ip": src_ip,
                "action": "PASS",
                "reason": reason,
                "timestamp": time.time()
            })
    
    return results
"""

# ===== Thêm function lấy status =====
"""
def get_ids_engine_status():
    '''Lấy trạng thái hiện tại của IDS Engine'''
    return get_ids_status()
"""

# =========================================================================
# 2. system.py - THAY ĐỔI apply_ips_decision
# =========================================================================

# ===== Thay đầu file =====
"""
# Existing imports...
from ids_onos_integration import process_ai_prediction, initialize_ids

# Remove old definitions:
# IP_PREDICTION_HISTORY = {}
# HISTORY_WINDOW = 5
# DROP_THRESHOLD = 3
"""

# ===== Thay hàm apply_ips_decision =====
"""
def apply_ips_decision(net, src_ip, label, confidence):
    '''
    PHIÊN BẢN MỚI: Xử lý quyết định IPS bằng IDS Engine
    
    Args:
        net: Mininet network object
        src_ip: IP nguồn
        label: Dự đoán (0-4)
        confidence: Độ tin cậy (0-1)
    
    Returns:
        action: "PASS", "MONITOR", "BLOCK"
    '''
    try:
        action, reason = process_ai_prediction(src_ip, label, confidence)
        
        # Logging
        if action == "BLOCK":
            print(f"[IPS] 🛡️  BLOCK {src_ip} - {reason}")
        elif action == "MONITOR":
            print(f"[IPS] 📊 MONITOR {src_ip}")
        
        return action
    
    except Exception as e:
        print(f"[IPS] Error processing {src_ip}: {e}")
        return "PASS"
"""

# ===== Trong start_network() function, thêm initialization =====
"""
def start_network():
    topo = ResearchTopo()
    
    # ... existing cleanup code ...
    
    # ===== THÊM: Initialize IDS Engine =====
    from ids_onos_integration import initialize_ids
    try:
        ids_engine = initialize_ids(use_onos=True)
        print("[*] IDS Engine initialized with ONOS")
    except Exception as e:
        print(f"[!] IDS initialization warning: {e}")
    
    # ... rest of start_network code ...
"""

# =========================================================================
# 3. Testfile - test_integration.py
# =========================================================================

"""
#!/usr/bin/env python3
# test_integration.py - Quick integration test

import torch
import numpy as np
from ai.config_v2 import (
    Anomaly_Autoencoder_Contrastive,
    DDos_ParallelFusion_CNN_GRU_Attention,
    FEATURE_NAMES, NUM_FEATURES_TOTAL, SEQ_LEN
)
from ai.train_colab_v2 import ContrastiveLoss
from ids_onos_integration import (
    IDSEngine, ONOSClient, OVSClient, 
    process_ai_prediction, initialize_ids
)

def test_autoencoder():
    print("[TEST 1] Contrastive Autoencoder")
    ae = Anomaly_Autoencoder_Contrastive(input_dim=NUM_FEATURES_TOTAL * SEQ_LEN)
    x = torch.randn(8, SEQ_LEN, NUM_FEATURES_TOTAL)
    recon, latent = ae(x)
    print(f"  Input shape: {x.shape}")
    print(f"  Latent shape: {latent.shape}")
    print(f"  Output shape: {recon.shape}")
    assert recon.shape == x.shape, "Shape mismatch!"
    print("  ✓ PASS\n")

def test_parallel_fusion():
    print("[TEST 2] Parallel Fusion CNN-GRU")
    model = DDos_ParallelFusion_CNN_GRU_Attention(input_dim=NUM_FEATURES_TOTAL)
    x = torch.randn(4, SEQ_LEN, NUM_FEATURES_TOTAL)
    logits, temporal_w, spatial_w = model(x)
    print(f"  Input shape: {x.shape}")
    print(f"  Logits shape: {logits.shape}")
    print(f"  Temporal weights shape: {temporal_w.shape}")
    print(f"  Spatial weights shape: {spatial_w.shape}")
    assert logits.shape == (4, 5), "Output shape mismatch!"
    print("  ✓ PASS\n")

def test_ids_engine():
    print("[TEST 3] IDS Engine")
    ids = initialize_ids(use_onos=False)  # OVS only for testing
    
    # Simulate attack sequence
    test_ip = "10.0.1.100"
    for i in range(5):
        action, reason = process_ai_prediction(test_ip, label=1, confidence=0.95)
        print(f"  Iteration {i+1}: {action}")
        if i >= 3:  # After 4 detections, should block
            assert action in ["MONITOR", "BLOCK"], f"Unexpected action: {action}"
    
    print("  ✓ PASS\n")

def test_onos_connectivity():
    print("[TEST 4] ONOS Connectivity")
    client = ONOSClient()
    connected = client.check_connectivity()
    print(f"  ONOS connected: {connected}")
    print("  ✓ PASS (ONOS may or may not be available)\n")

if __name__ == "__main__":
    print("=" * 60)
    print("INTEGRATION TEST - DDoS Detection v2.0")
    print("=" * 60 + "\n")
    
    test_autoencoder()
    test_parallel_fusion()
    test_ids_engine()
    test_onos_connectivity()
    
    print("=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("=" * 60)
"""

# =========================================================================
# 4. CONFIG UPDATE - Nếu muốn giữ backward compatibility
# =========================================================================

"""
# config.py - Thêm vào cuối file để import từ v2
# (Nếu bạn muốn code cũ vẫn work)

try:
    # Import v2 components nếu available
    from config_v2 import (
        DDos_ParallelFusion_CNN_GRU_Attention,
        Anomaly_Autoencoder_Contrastive,
        SDN_XAI_Explainer_Advanced,
        NUM_FEATURES_TOTAL
    )
except ImportError:
    pass
"""

# =========================================================================
# 5. REQUIREMENTS.txt UPDATE
# =========================================================================

"""
# Thêm vào requirements.txt (nếu chưa có)

# Existing packages...
torch>=1.9.0
numpy>=1.20.0
scikit-learn>=0.24.0
pandas>=1.2.0

# New requirement cho IDS
requests>=2.26.0  # Cho ONOS REST API

# Optional: Nếu dùng GPU
# torch-cuda-toolkit>=11.0
"""

# =========================================================================
# 6. BASH SETUP SCRIPT
# =========================================================================

"""
#!/bin/bash
# setup_v2.sh - Nhanh chóng setup v2.0

cd /home/tgf/Documents/DoAn_SDN

echo "[*] Checking files..."
ls -la ai/config_v2.py 2>/dev/null && echo "✓ config_v2.py" || echo "✗ config_v2.py MISSING"
ls -la ai/train_colab_v2.py 2>/dev/null && echo "✓ train_colab_v2.py" || echo "✗ train_colab_v2.py MISSING"
ls -la ids_onos_integration.py 2>/dev/null && echo "✓ ids_onos_integration.py" || echo "✗ ids_onos_integration.py MISSING"

echo "\n[*] Testing imports..."
python3 -c "from config_v2 import NUM_FEATURES_TOTAL; print(f'✓ Loaded config_v2 ({NUM_FEATURES_TOTAL} features)')" && \\
python3 -c "from ids_onos_integration import initialize_ids; print('✓ Loaded ids_onos_integration')" && \\
echo "\n✓ Setup complete!"
"""
