#!/usr/bin/env python3
"""
🔍 FLOW MONITOR - Chi tiết theo dõi traffic qua interface
Hiểu rõ: luồng nào đi qua, pass/reject bao nhiêu

Cách dùng:
  1. Khởi động attack (nếu test attack):
     containernet> py [net.get(f'h{i}').cmd('python3 attack/udp_flood.py 10.0.0.10 &') for i in range(1, 5)]
  
  2. Chạy monitor (Terminal khác):
     sudo ./sdn_env/bin/python3 ai/flow_monitor.py
  
  3. Chạy ~5-10 phút, sau đó Ctrl+C để dừng
"""

import os
import sys
import time
from collections import defaultdict
from nfstream import NFStreamer

# Filter config (match auto_dataset_generator.py)
TARGET_PORTS = {8000, 8080, 80, 443}
TARGET_SERVICES = {'10.0.0.10', '10.0.0.11', '10.0.0.20'}
SYSTEM_HOSTS_EXCLUDE = {'10.0.0.100', '10.0.0.101', '10.0.0.102',
                        '10.0.0.200', '10.0.0.201', '10.0.0.202', '10.0.0.20'}
RESTRICTED_PORTS = {22, 6633, 6653}

def _pick_attr(flow, *names, default=0):
    for name in names:
        if hasattr(flow, name):
            value = getattr(flow, name)
            if value is not None:
                return value
    return default

class FlowMonitor:
    def __init__(self, interface="s6-eth1", duration_sec=600):
        self.interface = interface
        self.duration_sec = duration_sec
        
        # Stats tracking
        self.stats = {
            'total_flows': 0,
            'pass_filter': 0,
            'reject_reasons': defaultdict(int),
            'by_subnet': defaultdict(int),
            'by_port': defaultdict(int),
            'by_protocol': defaultdict(int),
            'samples': []
        }
    
    def classify_subnet(self, ip):
        """Phân loại subnet từ IP."""
        if ip.startswith('10.0.1.'):
            return 'BOTNET'
        elif ip.startswith('10.0.2.'):
            return 'CLIENT'
        elif ip.startswith('10.0.0.'):
            return 'SERVICE'
        elif ip.startswith('172.'):
            return 'DOCKER'
        else:
            return 'OTHER'
    
    def check_filter(self, src_ip, dst_ip, src_port, dst_port):
        """Kiểm tra flow có pass filter không, return (pass, reason)."""
        
        # Filter 1: System hosts exclude
        if src_ip in SYSTEM_HOSTS_EXCLUDE or dst_ip in SYSTEM_HOSTS_EXCLUDE:
            return False, "SYSTEM_HOST"
        
        # Filter 2: DNS exclude
        if dst_port == 53:
            return False, "DNS_PORT_53"
        
        # Filter 3: Restricted ports
        if src_port in RESTRICTED_PORTS or dst_port in RESTRICTED_PORTS:
            return False, "RESTRICTED_PORT"
        
        # Filter 4: Attack or Client traffic
        is_attack_or_client = (src_ip.startswith("10.0.1.") or src_ip.startswith("10.0.2.") or
                              dst_ip.startswith("10.0.1.") or dst_ip.startswith("10.0.2."))
        
        # Filter 5: Web traffic (ACCEPT BOTH REQUEST + RESPONSE)
        # REQUEST: 10.0.1/2.x → 10.0.0.10:8000
        # RESPONSE: 10.0.0.10:8000 → 10.0.1/2.x:random_port
        is_web_traffic = (
            (dst_ip in TARGET_SERVICES or dst_port in TARGET_PORTS) or  # Request
            (src_ip in TARGET_SERVICES and src_port in TARGET_PORTS)     # Response
        )
        
        if not is_attack_or_client:
            return False, "NOT_ATTACK_CLIENT"
        
        if not is_web_traffic:
            return False, "NOT_WEB_TRAFFIC"
        
        return True, "PASS"
    
    def run(self):
        """Main monitoring loop."""
        print(f"\n{'='*80}")
        print(f"🔍 FLOW MONITOR - Interface: {self.interface}")
        print(f"{'='*80}")
        print(f"⏱️  Running for {self.duration_sec}s (~{self.duration_sec//60}m)...\n")
        
        try:
            streamer = NFStreamer(
                source=self.interface,
                promiscuous_mode=True,
                idle_timeout=1,
                active_timeout=5,
                accounting_mode=0,
                n_dissections=20,
                statistical_analysis=True
            )
            
            start_time = time.time()
            last_print = start_time
            
            for flow in streamer:
                now = time.time()
                
                # Skip invalid
                if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                    continue
                
                src_ip = flow.src_ip
                dst_ip = flow.dst_ip
                src_port = flow.src_port
                dst_port = flow.dst_port
                
                # Check filter
                passes, reason = self.check_filter(src_ip, dst_ip, src_port, dst_port)
                
                self.stats['total_flows'] += 1
                if passes:
                    self.stats['pass_filter'] += 1
                else:
                    self.stats['reject_reasons'][reason] += 1
                
                # Classify
                src_subnet = self.classify_subnet(src_ip)
                dst_subnet = self.classify_subnet(dst_ip)
                flow_type = f"{src_subnet}→{dst_subnet}"
                self.stats['by_subnet'][flow_type] += 1
                self.stats['by_port'][dst_port] += 1
                
                proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(flow.protocol, f'P{flow.protocol}')
                self.stats['by_protocol'][proto_name] += 1
                
                # Sample first 30 flows
                if len(self.stats['samples']) < 30:
                    self.stats['samples'].append({
                        'src': f"{src_ip}:{src_port}",
                        'dst': f"{dst_ip}:{dst_port}",
                        'proto': proto_name,
                        'subnet': flow_type,
                        'passes': passes,
                        'reason': reason
                    })
                
                # Print progress every 3s
                if now - last_print >= 3.0:
                    elapsed = int(now - start_time)
                    total = self.stats['total_flows']
                    passed = self.stats['pass_filter']
                    pass_rate = 100 * passed / max(1, total)
                    
                    print(f"[{elapsed:3d}s] Flows: {total:5d} | Pass: {passed:5d} ({pass_rate:5.1f}%) | "
                          f"BOTNET→SERVICE: {self.stats['by_subnet'].get('BOTNET→SERVICE', 0):5d} | "
                          f"CLIENT→SERVICE: {self.stats['by_subnet'].get('CLIENT→SERVICE', 0):5d}", end='\r')
                    last_print = now
                
                # Timeout
                if now - start_time >= self.duration_sec:
                    break
        
        except KeyboardInterrupt:
            print("\n[*] Dừng monitor (Ctrl+C)")
        except Exception as e:
            print(f"\n[ERROR] {e}")
        
        self.print_report()
    
    def print_report(self):
        """In báo cáo chi tiết."""
        total = self.stats['total_flows']
        passed = self.stats['pass_filter']
        pass_rate = 100 * passed / max(1, total)
        
        print(f"\n{'='*80}")
        print(f"📊 DETAILED REPORT")
        print(f"{'='*80}\n")
        
        print(f"📈 OVERALL STATISTICS:")
        print(f"  Total flows captured:  {total:,}")
        print(f"  Flows passing filter:  {passed:,} ({pass_rate:.1f}%)")
        print(f"  Flows rejected:        {total - passed:,} ({100 - pass_rate:.1f}%)\n")
        
        print(f"🔗 FLOW TYPES (Source→Destination Subnet):")
        for flow_type, count in sorted(self.stats['by_subnet'].items(), key=lambda x: -x[1]):
            pct = 100 * count / max(1, total)
            print(f"  {flow_type:20s}: {count:5d} ({pct:5.1f}%)")
        
        print(f"\n🚫 REJECTION REASONS:")
        if self.stats['reject_reasons']:
            for reason, count in sorted(self.stats['reject_reasons'].items(), key=lambda x: -x[1]):
                pct = 100 * count / max(1, total - passed)
                print(f"  {reason:20s}: {count:5d} ({pct:5.1f}% of rejects)")
        else:
            print(f"  (All flows passed!)")
        
        print(f"\n📍 DESTINATION PORT DISTRIBUTION:")
        for port, count in sorted(self.stats['by_port'].items(), key=lambda x: -x[1])[:10]:
            pct = 100 * count / max(1, total)
            print(f"  Port {port:5d}: {count:5d} ({pct:5.1f}%)")
        
        print(f"\n🔀 PROTOCOL DISTRIBUTION:")
        for proto, count in sorted(self.stats['by_protocol'].items(), key=lambda x: -x[1]):
            pct = 100 * count / max(1, total)
            print(f"  {proto:6s}: {count:5d} ({pct:5.1f}%)")
        
        print(f"\n🎯 SAMPLE FLOWS (first 30):")
        for i, flow in enumerate(self.stats['samples'], 1):
            status = "✅ PASS" if flow['passes'] else f"❌ {flow['reason']}"
            print(f"  {i:2d}. {flow['src']:25s} → {flow['dst']:25s} [{flow['proto']:4s}] {flow['subnet']:15s} {status}")
        
        print(f"\n{'='*80}")
        print(f"✅ Monitor completed successfully!")
        print(f"{'='*80}\n")

if __name__ == "__main__":
    monitor = FlowMonitor(interface="s6-eth1", duration_sec=600)  # 10 minutes
    monitor.run()
