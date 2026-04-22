#!/usr/bin/env python3
"""
🔬 INTERFACE DIAGNOSTIC TOOL
Tìm kiếm interface tốt nhất cho data collection bằng cách:
1. Capture gói tin từ từng interface
2. Phân loại theo subnet (client, botnet, services)
3. Kiểm tra filter match rate
4. Khuyến nghị interface tốt nhất
"""

import os
import sys
import json
import time
from collections import defaultdict
from nfstream import NFStreamer

def _pick_attr(flow, *names, default=0):
    for name in names:
        if hasattr(flow, name):
            value = getattr(flow, name)
            if value is not None:
                return value
    return default

def analyze_interface(iface_name, sample_size=500, timeout_sec=30):
    """Phân tích interface bằng cách capture N flow."""
    
    print(f"\n{'='*70}")
    print(f"🔍 Analyzing Interface: {iface_name}")
    print(f"{'='*70}")
    
    stats = {
        'interface': iface_name,
        'total_flows': 0,
        'by_subnet': defaultdict(int),
        'by_protocol': defaultdict(int),
        'src_ips': set(),
        'dst_ips': set(),
        'client_flows': 0,  # 10.0.2.x
        'botnet_flows': 0,  # 10.0.1.x
        'service_flows': 0, # 10.0.0.x
        'filter_pass': 0,   # SMART filter
        'samples': []
    }
    
    try:
        streamer = NFStreamer(
            source=iface_name,
            promiscuous_mode=True,
            idle_timeout=1,
            active_timeout=5,
            n_dissections=20,
            statistical_analysis=True
        )
        
        start_time = time.time()
        flow_count = 0
        
        for flow in streamer:
            # Skip invalid/internal
            if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                continue
            if flow.src_port in {22, 6633, 6653} or flow.dst_port in {22, 6633, 6653}:
                continue
            if flow.protocol == 1:  # ICMP
                continue
            
            flow_count += 1
            stats['total_flows'] += 1
            stats['src_ips'].add(flow.src_ip)
            stats['dst_ips'].add(flow.dst_ip)
            
            # Classify by subnet
            if flow.src_ip.startswith('10.0.2.') or flow.dst_ip.startswith('10.0.2.'):
                subnet = 'CLIENT'
                stats['client_flows'] += 1
            elif flow.src_ip.startswith('10.0.1.') or flow.dst_ip.startswith('10.0.1.'):
                subnet = 'BOTNET'
                stats['botnet_flows'] += 1
            elif flow.src_ip.startswith('10.0.0.') or flow.dst_ip.startswith('10.0.0.'):
                subnet = 'SERVICE'
                stats['service_flows'] += 1
            elif flow.src_ip.startswith('172.') or flow.dst_ip.startswith('172.'):
                subnet = 'DOCKER'
            else:
                subnet = 'OTHER'
            
            stats['by_subnet'][subnet] += 1
            
            # Protocol
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(flow.protocol, f'P{flow.protocol}')
            stats['by_protocol'][proto_name] += 1
            
            # Check if flow matches SMART filter (bản mới trong auto_dataset_generator)
            src_ip = flow.src_ip
            dst_ip = flow.dst_ip
            src_port = flow.src_port
            dst_port = flow.dst_port
            
            # Filter logic từ auto_dataset_generator (SMART_SUBNET_FILTER)
            # ✅ UPDATED: Include botnet (10.0.1.x) for attack traffic
            TARGET_PORTS = {8000, 8080, 80, 443}
            TARGET_SERVICES = {'10.0.0.10', '10.0.0.11', '10.0.0.20'}
            SYSTEM_HOSTS_EXCLUDE = {'10.0.0.100', '10.0.0.101', '10.0.0.102', 
                                   '10.0.0.200', '10.0.0.201', '10.0.0.202', '10.0.0.20'}
            
            # System filter (exclude monitoring/services)
            if src_ip in SYSTEM_HOSTS_EXCLUDE or dst_ip in SYSTEM_HOSTS_EXCLUDE:
                continue
            
            # DNS filter (exclude port 53)
            if dst_port == 53:
                continue
            
            # Attack/Client filter (INCLUDE BOTH 10.0.1.x AND 10.0.2.x)
            is_attack_or_client = (src_ip.startswith("10.0.1.") or src_ip.startswith("10.0.2.") or
                                  dst_ip.startswith("10.0.1.") or dst_ip.startswith("10.0.2."))
            
            # Web filter
            is_web_traffic = (dst_ip in TARGET_SERVICES or dst_port in TARGET_PORTS)
            
            if is_attack_or_client and is_web_traffic:
                stats['filter_pass'] += 1
            
            # Sample first 20 flows
            if len(stats['samples']) < 20:
                stats['samples'].append({
                    'src': f"{src_ip}:{src_port}",
                    'dst': f"{dst_ip}:{dst_port}",
                    'proto': proto_name,
                    'passes_filter': is_attack_or_client and is_web_traffic
                })
            
            # Timeout check
            if time.time() - start_time > timeout_sec:
                break
            
            if flow_count >= sample_size:
                break
        
        stats['capture_duration'] = time.time() - start_time
        
    except Exception as e:
        print(f"❌ Error capturing on {iface_name}: {e}")
        return None
    
    return stats

def print_analysis(stats):
    """Pretty print kết quả phân tích."""
    
    if stats is None:
        print("❌ No data captured")
        return
    
    iface = stats['interface']
    total = stats['total_flows']
    
    print(f"\n📊 Summary for {iface}:")
    print(f"  Total flows captured: {total}")
    print(f"  Capture duration: {stats['capture_duration']:.1f}s")
    
    if total == 0:
        print("  ⚠️  No flows captured!")
        return
    
    print(f"\n🔗 Subnet Distribution:")
    for subnet, count in sorted(stats['by_subnet'].items(), key=lambda x: -x[1]):
        pct = 100 * count / total
        print(f"  {subnet:8s}: {count:5d} ({pct:5.1f}%)")
    
    print(f"\n📋 Filter Analysis (SMART):")
    pass_rate = 100 * stats['filter_pass'] / max(1, total)
    print(f"  Flows passing filter: {stats['filter_pass']} / {total} ({pass_rate:.1f}%)")
    print(f"  Client flows: {stats['client_flows']}")
    print(f"  Botnet flows: {stats['botnet_flows']}")
    print(f"  Service flows: {stats['service_flows']}")
    
    print(f"\n🎯 Sample Flows (first 20):")
    for i, flow in enumerate(stats['samples'], 1):
        status = "✅" if flow['passes_filter'] else "❌"
        print(f"  {i:2d}. {flow['src']:20s} → {flow['dst']:20s} [{flow['proto']:4s}] {status}")
    
    print(f"\n📍 Unique Source IPs: {len(stats['src_ips'])}")
    print(f"📍 Unique Dest IPs: {len(stats['dst_ips'])}")

def find_best_interface():
    """🎯 Tự động tìm best interface - ưu tiên s6-eth1 (L3 backbone)."""
    
    try:
        nets = set(os.listdir("/sys/class/net"))
    except:
        nets = set()
    
    # ✅ TEST ORDER: s6-eth1 FIRST (L3 backbone, optimal)
    # Fallback: s6-eth4, s1-eth3, h82-eth1
    candidates = ["s6-eth1", "s6-eth4", "s1-eth3", "h82-eth1"]
    candidates = [c for c in candidates if c in nets]
    
    if not candidates:
        print("❌ No candidate interfaces found!")
        return
    
    results = []
    for iface in candidates:
        stats = analyze_interface(iface, sample_size=300, timeout_sec=20)
        print_analysis(stats)
        if stats:
            results.append(stats)
    
    # Score each interface
    print(f"\n{'='*70}")
    print("🏆 RANKING INTERFACES (by filter pass rate)")
    print(f"{'='*70}\n")
    
    for stats in sorted(results, key=lambda x: -x['filter_pass']):
        iface = stats['interface']
        total = stats['total_flows']
        pass_rate = 100 * stats['filter_pass'] / max(1, total) if total > 0 else 0
        client_rate = 100 * stats['client_flows'] / max(1, total) if total > 0 else 0
        botnet_rate = 100 * stats['botnet_flows'] / max(1, total) if total > 0 else 0
        
        score = pass_rate + (client_rate * 0.5)  # Prioritize filter pass
        
        quality = "🟢 EXCELLENT" if pass_rate > 95 else "🟡 GOOD" if pass_rate > 80 else "🔴 POOR"
        print(f"  {iface:10s} │ Total: {total:4d} │ Filter: {pass_rate:5.1f}% │ "
              f"Client: {client_rate:5.1f}% │ Botnet: {botnet_rate:5.1f}% │ {quality}")
    
    # Recommend best
    if results:
        best = max(results, key=lambda x: (
            x['filter_pass'] / max(1, x['total_flows']),
            x['client_flows']
        ))
        best_rate = 100 * best['filter_pass'] / max(1, best['total_flows'])
        
        print(f"\n✅ RECOMMENDED INTERFACE: {best['interface']}")
        print(f"   Filter Pass Rate: {best_rate:.1f}%")
        print(f"   Reason: {best['interface']} is L3 backbone - preserves original IPs, captures REQUEST+RESPONSE")
        
        if best['interface'] == 's6-eth1':
            print(f"\n   ⭐ s6-eth1 = OPTIMAL CHOICE")
            print(f"      • Captures traffic between s1 (CORE) and s6 (WEB SERVER SWITCH)")
            print(f"      • Both botnet (10.0.1.x) and client (10.0.2.x) flows")
            print(f"      • NO SNAT - original IPs preserved")
            print(f"      • Filter works perfectly with bidirectional flows")
        elif best['interface'] == 's6-eth4':
            print(f"\n   ⚠️  s6-eth4 = FALLBACK (slightly lower performance)")
        else:
            print(f"\n   ℹ️  {best['interface']} = AVAILABLE (limited topology visibility)")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Test specific interface
        iface = sys.argv[1]
        stats = analyze_interface(iface, sample_size=500, timeout_sec=30)
        print_analysis(stats)
    else:
        # Auto-detect best interface
        find_best_interface()
