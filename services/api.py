#services/api.py
#!/usr/bin/env python3
"""
API Server for DOAn_SDN Network
Exposes network statistics and control endpoints
Connects to PostgreSQL database (db1 @ 10.0.0.20)
"""

import socket
import threading
import json
import time
from datetime import datetime
import sys
import os

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class APIServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.running = False
        self.stats = {
            'requests': 0,
            'bytes_sent': 0,
            'start_time': datetime.now().isoformat(),
            'connections': []
        }
        
    def start(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.running = True
            
            print(f"[API] Server started on {self.host}:{self.port}")
            print(f"[API] Database: 10.0.0.20:5432")
            print(f"[API] Connected hosts can:          ")
            print(f"      GET  /stats -- Show network stats")
            print(f"      GET  /health -- Health check")
            print(f"      POST /alert -- Report anomalies")
            
            while self.running:
                try:
                    client_socket, addr = server_socket.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    ).start()
                except Exception as e:
                    print(f"[API] Accept error: {e}")
                    
        except Exception as e:
            print(f"[API] Failed to start: {e}")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket, addr):
        try:
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            self.stats['requests'] += 1
            self.stats['connections'].append({
                'ip': addr[0],
                'time': datetime.now().isoformat()
            })
            if len(self.stats['connections']) > 1000:
                self.stats['connections'].pop(0)
            # Parse HTTP request
            lines = request.split('\r\n')
            method_line = lines[0].split(' ')
            
            if len(method_line) >= 2:
                method = method_line[0]
                path = method_line[1]
                
                print(f"[API] {method} {path} from {addr[0]}")
                
                if path == '/stats':
                    response = self.stats_response()
                elif path == '/health':
                    response = self.health_response()
                elif path == '/alert' and method == 'POST':
                    response = self.handle_alert(request)
                else:
                    response = self.not_found_response()
                
                client_socket.sendall(response.encode('utf-8'))
            
        except Exception as e:
            print(f"[API] Error handling client: {e}")
        finally:
            client_socket.close()
    
    def stats_response(self):
        """Return JSON stats"""
        body = json.dumps(self.stats, indent=2)
        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n" + body
        )
    
    def health_response(self):
        """Health check endpoint"""
        body = json.dumps({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n" + body
        )
    
    def handle_alert(self, request):
        """Handle alert submissions from IDS"""
        try:
            # Parse POST body
            body_start = request.find('\r\n\r\n') + 4
            alert_json = request[body_start:]
            alert = json.loads(alert_json) if alert_json else {}
            
            print(f"[API] Received alert: {alert}")
            # In production, write to database
            
            response_body = json.dumps({'alert_id': len(self.stats['connections']), 'stored': True})
            return (
                "HTTP/1.1 201 Created\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + response_body
            )
        except Exception as e:
            print(f"[API] Alert error: {e}")
            body = json.dumps({'error': str(e)})
            return (
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
    
    def not_found_response(self):
        """404 response"""
        body = json.dumps({'error': 'Not found'})
        return (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n" + body
        )

if __name__ == '__main__':
    server = APIServer(host='0.0.0.0', port=5000)
    print("[API] DOAn_SDN API Service")
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[API] Shutting down...")
        server.running = False
