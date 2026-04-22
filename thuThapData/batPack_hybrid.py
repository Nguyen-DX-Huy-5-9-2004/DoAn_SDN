#!/usr/bin/env python3
"""
🌊 HYBRID PACKET CAPTURE - Dual Interface Mode
Capture từ 2 interface cùng lúc để gather TOÀN BỘ traffic:
- s1-eth3: Client traffic (10.0.2.x → 10.0.0.10)
- s1-eth2: Botnet traffic (10.0.1.x → 10.0.0.10)

Merge output vào single zeek_stream.json
"""

import json
import os
import time
import threading
from nfstream import NFStreamer

OUTPUT_FIFO = "zeek_stream.json"
FLUSH_BATCH_SIZE = 50
FLUSH_INTERVAL = 1.0
RESTRICTED_PORTS = {22, 6633, 6653}

def _pick_attr(flow, *names, default=0):
    for name in names:
        if hasattr(flow, name):
            value = getattr(flow, name)
            if value is not None:
                return value
    return default

def _detect_interfaces():
    """Detect s1-eth2 and s1-eth3 for hybrid capture."""
    try:
        nets = set(os.listdir("/sys/class/net"))
    except Exception:
        nets = set()
    
    ifaces = []
    if "s1-eth3" in nets:
        ifaces.append("s1-eth3")
        print("[HYBRID] Found s1-eth3 (Client distribution link)")
    if "s1-eth2" in nets:
        ifaces.append("s1-eth2")
        print("[HYBRID] Found s1-eth2 (Botnet distribution link)")
    
    return ifaces

def capture_flow_stream(iface, output_queue):
    """Capture flows từ single interface, push vào queue."""
    
    print(f"[HYBRID] Starting capture thread for {iface}...")
    
    try:
        streamer = NFStreamer(
            source=iface,
            promiscuous_mode=True,
            idle_timeout=1,
            active_timeout=5,
            accounting_mode=0,
            n_dissections=20,
            statistical_analysis=True
        )
        
        for flow in streamer:
            # Filter invalid traffic
            if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                continue
            if flow.src_port in RESTRICTED_PORTS or flow.dst_port in RESTRICTED_PORTS:
                continue
            if flow.protocol == 1:  # ICMP
                continue
            
            # Extract features (match batPack123.py structure)
            duration_sec = flow.bidirectional_duration_ms / 1000.0
            if duration_sec <= 0:
                duration_sec = 0.001
            
            src_bytes = _pick_attr(flow, "src2dst_bytes", "src_to_dst_bytes", default=0)
            dst_bytes = _pick_attr(flow, "dst2src_bytes", "dst_to_src_bytes", default=0)
            src_packets = _pick_attr(flow, "src2dst_packets", "src_to_dst_packets", default=0)
            dst_packets = _pick_attr(flow, "dst2src_packets", "dst_to_src_packets", default=0)
            
            # conn_state
            conn_state = 0
            if flow.protocol == 6:  # TCP
                conn_state = 1 if flow.bidirectional_packets >= 3 else 0
            elif flow.protocol == 17:  # UDP
                conn_state = 2
            
            # l7_proto
            l7_proto = 0
            app_name = str(_pick_attr(flow, "application_name", default="")).upper()
            if "HTTP" in app_name:
                l7_proto = 1
            elif "TLS" in app_name or "SSL" in app_name:
                l7_proto = 2
            elif "DNS" in app_name:
                l7_proto = 3
            elif "OPENFLOW" in app_name:
                l7_proto = 5
            
            # anomaly_score
            is_weird = 0
            if src_packets > 10 and dst_packets == 0:
                is_weird = 1
            elif src_packets > 100 and (src_packets / max(1, dst_packets)) > 50:
                is_weird = 1
            
            # Build flow data
            data = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "interface": iface,  # Track which interface captured this
                "features": [
                    flow.src_port, flow.dst_port, flow.protocol, round(duration_sec, 4),
                    src_bytes, dst_bytes,
                    src_packets, dst_packets,
                    conn_state, l7_proto,
                    round(flow.bidirectional_packets / duration_sec, 2),
                    round(flow.bidirectional_bytes / duration_sec, 2),
                    is_weird
                ]
            }
            
            output_queue.append(json.dumps(data))
    
    except Exception as e:
        print(f"[HYBRID] Error on {iface}: {e}")

def main():
    # Clean up old FIFO
    if os.path.exists(OUTPUT_FIFO):
        try:
            os.remove(OUTPUT_FIFO)
        except:
            pass
    
    # Create FIFO
    try:
        os.mkfifo(OUTPUT_FIFO)
        print(f"[HYBRID] Created Named Pipe: {OUTPUT_FIFO}")
    except OSError:
        pass
    
    # Detect interfaces
    ifaces = _detect_interfaces()
    if not ifaces:
        print("[HYBRID] ❌ No suitable interfaces found!")
        return
    
    print(f"[HYBRID] Starting HYBRID capture mode with {len(ifaces)} interface(s)...")
    
    # Shared output queue
    output_queue = []
    last_flush = time.time()
    
    # Start capture threads
    threads = []
    for iface in ifaces:
        t = threading.Thread(target=capture_flow_stream, args=(iface, output_queue), daemon=True)
        t.start()
        threads.append(t)
    
    try:
        with open(OUTPUT_FIFO, "w", buffering=1) as f:
            while True:
                # Flush queue periodically or when large enough
                now = time.time()
                if output_queue and (len(output_queue) >= FLUSH_BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL):
                    f.write("\n".join(output_queue) + "\n")
                    f.flush()
                    output_queue.clear()
                    last_flush = now
                
                time.sleep(0.01)
    
    except KeyboardInterrupt:
        print("[HYBRID] Stopping capture...")
    except Exception as e:
        print(f"[HYBRID] Error: {e}")
    finally:
        if os.path.exists(OUTPUT_FIFO):
            os.remove(OUTPUT_FIFO)

if __name__ == "__main__":
    main()
