#services/dns.py
#!/usr/bin/env python3
"""
DNS Server for DOAn_SDN
Listens on UDP 53 for DNS queries and responds to local network
"""

import socket
import threading
import json
from datetime import datetime

# DNS response templates
DNS_HEADER = b'\x00\x80\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00'

class DNSServer:
    def __init__(self, host='0.0.0.0', port=53):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # Local records
        self.records = {
            'web.local': '10.0.0.100',
            'api.local': '10.0.0.102',
            'db.local': '10.0.0.20',
            'localhost': '127.0.0.1',
        }
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True
            print(f"[DNS] Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(512)
                    #threading.Thread(target=self.handle_query, args=(data, addr)).start()
                    self.handle_query(data, addr)
                except Exception as e:
                    print(f"[DNS] Error: {e}")
                    
        except Exception as e:
            print(f"[DNS] Failed to start: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def handle_query(self, data, addr):
        try:
            # Simple DNS query parsing
            query = data[12:].decode('utf-8', errors='ignore').split('\x00')[0]
            
            # Check if we have this record
            for domain, ip in self.records.items():
                if domain.lower() in query.lower():
                    print(f"[DNS] Query: {domain} -> {ip} from {addr}")
                    self.send_response(addr, ip)
                    return
            
            print(f"[DNS] Unknown query: {query} from {addr}")
        except Exception as e:
            print(f"[DNS] Error handling query: {e}")
    
    def send_response(self, addr, ip):
        try:
            # Simple A record response
            response = DNS_HEADER
            # Convert IP to bytes
            ip_parts = [int(x) for x in ip.split('.')]
            response += bytes(ip_parts)
            self.socket.sendto(response, addr)
        except Exception as e:
            print(f"[DNS] Error sending response: {e}")

if __name__ == '__main__':
    server = DNSServer()
    print("[DNS] DOAn_SDN DNS Service")
    server.start()
