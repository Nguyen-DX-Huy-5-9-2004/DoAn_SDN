import unittest
import torch
import numpy as np
import os
import sys

# Thêm đường dẫn để import config
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import DDos_CNN_GRU_Attention, Anomaly_Autoencoder, SDN_XAI_Explainer, NUM_FEATURES, SEQ_LEN, NUM_CLASSES

class TestClass2Classifier(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        cls.model = DDos_CNN_GRU_Attention().to(cls.device)
        cls.ae = Anomaly_Autoencoder().to(cls.device)
        cls.explainer = SDN_XAI_Explainer([f"Feature_{i}" for i in range(NUM_FEATURES)])
        cls.model.eval()
        cls.ae.eval()

    def test_model_output_shape(self):
        """Test xem output của model có đúng format [Batch, Classes] không"""
        batch_size = 32
        dummy_input = torch.randn(batch_size, SEQ_LEN, NUM_FEATURES).to(self.device)
        output, attn_weights = self.model(dummy_input)
        
        self.assertEqual(output.shape, (batch_size, NUM_CLASSES))
        self.assertEqual(attn_weights.shape, (batch_size, SEQ_LEN))
        
        # Kiểm tra tổng trọng số attention xấp xỉ 1 (Softmax)
        sum_attn = torch.sum(attn_weights, dim=1)
        for s in sum_attn:
            self.assertAlmostEqual(s.item(), 1.0, places=5)

    def test_ae_reconstruction_shape(self):
        """Test xem Autoencoder có tái tạo đúng kích thước input không"""
        batch_size = 16
        dummy_input = torch.randn(batch_size, SEQ_LEN, NUM_FEATURES).to(self.device)
        reconstructed = self.ae(dummy_input)
        self.assertEqual(reconstructed.shape, dummy_input.shape)

    def test_xai_explainer(self):
        """Test module giải thích AI (XAI)"""
        dummy_input = torch.randn(1, SEQ_LEN, NUM_FEATURES)
        dummy_attn = torch.zeros(1, SEQ_LEN)
        dummy_attn[0, 5] = 1.0 # Giả lập flow thứ 5 là quan trọng nhất
        
        explanation = self.explainer.explain(dummy_input, dummy_attn)
        
        self.assertEqual(explanation['top_flow_index'], 5)
        self.assertIn('top_features', explanation)
        self.assertTrue(len(explanation['top_features']) > 0)

    def test_latency_requirement(self):
        """Test yêu cầu Latency < 100ms"""
        dummy_input = torch.randn(1, SEQ_LEN, NUM_FEATURES).to(self.device)
        import time
        
        # Warm up
        _ = self.model(dummy_input)
        
        start_time = time.time()
        for _ in range(100):
            _ = self.model(dummy_input)
        avg_latency = (time.time() - start_time) / 100 * 1000 # ms
        
        print(f"\n[LATENCY TEST] Average: {avg_latency:.2f}ms")
        self.assertLess(avg_latency, 100.0)

    def test_throughput_requirement(self):
        """Test yêu cầu Throughput > 1000 flows/sec"""
        batch_size = 1000
        dummy_input = torch.randn(batch_size, SEQ_LEN, NUM_FEATURES).to(self.device)
        import time
        
        start_time = time.time()
        _ = self.model(dummy_input)
        duration = time.time() - start_time
        throughput = batch_size / duration
        
        print(f"[THROUGHPUT TEST] {throughput:.2f} sequences/sec")
        self.assertGreater(throughput, 1000.0)

if __name__ == '__main__':
    unittest.main()
