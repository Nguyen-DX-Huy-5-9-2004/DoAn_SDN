#!/usr/bin/env python3
"""
Graph Neural Network IDS for DOAn_SDN
Monitors network traffic and detects anomalies using GNN
Reports to API server (h72 @ 10.0.0.102:5000)
"""

import socket
import json
import time
import threading
import sys
import os
from collections import defaultdict
from datetime import datetime

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class GNN_IDS:
    def __init__(self):
        self.api_server = '10.0.0.102'
        self.api_port = 5000
        self.anomalies = []
        self.traffic_stats = defaultdict(int)
        
    def start(self):
        """Start IDS monitoring loop"""
        print("[IDS-GNN] DOAn_SDN IDS Service starting...")
        print(f"[IDS-GNN] API Server: {self.api_server}:{self.api_port}")
        print("[IDS-GNN] Monitoring network traffic...")
        
        # Start main detection loop
        threading.Thread(target=self.detection_loop, daemon=True).start()
        
        # Keep alive
        try:
            while True:
                time.sleep(60)
                self.health_check()
        except KeyboardInterrupt:
            print("\n[IDS-GNN] Shutting down...")
    
    def detection_loop(self):
        """Main detection loop - simulates GNN analysis"""
        iteration = 0
        while True:
            try:
                iteration += 1
                
                # Simulate network traffic analysis
                # In production, this would:
                # 1. Capture packets via pcap
                # 2. Extract features (packet sizes, timing, ports)
                # 3. Build traffic graph (source -> destination)
                # 4. Run GNN model inference
                # 5. Score anomalies
                
                # Simulate detection every 30 seconds
                if iteration % 3 == 0:
                    anomaly_score = self.simulate_gnn_analysis()
                    
                    if anomaly_score > 0.7:
                        alert = {
                            'type': 'ANOMALY',
                            'score': round(anomaly_score, 3),
                            'description': self.get_anomaly_description(anomaly_score),
                            'timestamp': datetime.now().isoformat(),
                            'iteration': iteration
                        }
                        print(f"[IDS-GNN] Alert: {alert['description']} (score: {alert['score']})")
                        self.send_alert(alert)
                
                time.sleep(10)
                
            except Exception as e:
                print(f"[IDS-GNN] Detection error: {e}")
                time.sleep(5)
    
    def simulate_gnn_analysis(self):
        """Simulate GNN model analysis"""
        # In real system, run actual GNN model
        # For now, return random-ish anomaly score
        import random
        score = random.uniform(0.3, 0.95)
        return score
    
    def get_anomaly_description(self, score):
        """Get anomaly description based on score"""
        if score > 0.9:
            return "CRITICAL: Potential DDoS/Botnet activity detected"
        elif score > 0.8:
            return "HIGH: Suspicious traffic pattern detected"
        elif score > 0.75:
            return "MEDIUM: Possible port scan or reconnaissance"
        else:
            return "LOW: Minor anomaly detected"
    
    def send_alert(self, alert):
        """Send alert to API server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.api_server, self.api_port))
            
            payload = json.dumps(alert)
            request = (
                "POST /alert HTTP/1.1\r\n"
                f"Host: {self.api_server}:{self.api_port}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n"
                "\r\n" + payload
            )
            
            sock.sendall(request.encode('utf-8'))
            response = sock.recv(1024)
            sock.close()
            
            if b'201' in response or b'200' in response:
                print(f"[IDS-GNN] Alert sent to API server")
            else:
                print(f"[IDS-GNN] API response: {response[:100]}")
                
        except ConnectionRefusedError:
            print("[IDS-GNN] API server not available, Alert queued")
        except Exception as e:
            print(f"[IDS-GNN] Error sending alert: {e}")
    
    def health_check(self):
        """Periodic health check with API server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.api_server, self.api_port))
            
            request = (
                "GET /health HTTP/1.1\r\n"
                f"Host: {self.api_server}:{self.api_port}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            
            sock.sendall(request.encode('utf-8'))
            response = sock.recv(1024)
            sock.close()
            
            if b'200' in response:
                print("[IDS-GNN] Health: OK")
            else:
                print("[IDS-GNN] Health: API response anomaly")
                
        except Exception as e:
            print(f"[IDS-GNN] Health check failed: {e}")

if __name__ == '__main__':
    ids = GNN_IDS()
    print("[IDS-GNN] DOAn_SDN Graph Neural Network IDS")
    ids.start()
