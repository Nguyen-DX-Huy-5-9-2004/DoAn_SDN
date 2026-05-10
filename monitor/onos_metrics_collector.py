import json
import os
import time
from collections import defaultdict

import requests
from requests.auth import HTTPBasicAuth


ONOS_BASE = os.environ.get("ONOS_BASE", "http://127.0.0.1:8181/onos/v1")
AUTH = HTTPBasicAuth(
    os.environ.get("ONOS_USER", "onos"),
    os.environ.get("ONOS_PASS", "rocks"),
)
INTERVAL = float(os.environ.get("ONOS_METRIC_INTERVAL", "2"))
OUT_DIR = "monitor/runtime"
OUT_FILE = os.path.join(OUT_DIR, "onos_metrics.json")

# Protected infrastructure IPs (servers that should not be counted as "attackers")
INFRA_IPS = {"10.0.0.10", "10.0.0.11", "10.0.0.20"}  # proxy1, web1, db1
# Web server IP to monitor for "Effective Traffic"
WEB_SERVER_IP = "10.0.0.11"


def get_json(path):
    # Reduced timeout to avoid blocking too long, let loop handle retry
    r = requests.get(f"{ONOS_BASE}/{path}", auth=AUTH, timeout=3)
    r.raise_for_status()
    return r.json()


def build_host_port_map(hosts):
    """Build bidirectional mapping: (device, port) <-> IP"""
    port_to_ip = {}
    ip_to_port = {}
    for host in hosts:
        ips = host.get("ipAddresses", [])
        locations = host.get("locations", [])
        for loc in locations:
            element = loc.get("elementId")
            port = str(loc.get("port"))
            if element and port and ips:
                ip = ips[0]
                port_to_ip[(element, port)] = ip
                ip_to_port[ip] = (element, port)
    return port_to_ip, ip_to_port


def get_web_server_port_key(ip_to_port, web_ip=WEB_SERVER_IP):
    """Get the (device, port) key where web server is connected"""
    return ip_to_port.get(web_ip)


def collect():
    try:
        hosts = get_json("hosts").get("hosts", [])
        stats = get_json("statistics/ports").get("statistics", [])
        flows = get_json("flows").get("flows", [])
    except Exception as e:
        print(f"[COLLECTOR] ONOS Error: {e}")
        return None

    port_ip_map, ip_to_port = build_host_port_map(hosts)
    web_port_key = get_web_server_port_key(ip_to_port)

    flow_count_by_device = defaultdict(int)
    for flow in flows:
        did = flow.get("deviceId")
        if did:
            flow_count_by_device[did] += 1

    now = time.time()
    if not hasattr(collect, "_prev"):
        collect._prev = {}
        collect._prev_web = {}  # Separate tracking for web server port
        collect._prev_time = now

    dt = max(now - collect._prev_time, 0.001)
    rows = []
    
    # [3-TIER] Traffic categorization
    raw_incoming_packets = 0
    raw_incoming_bytes = 0
    effective_packets = 0
    effective_bytes = 0
    
    for dev in stats:
        did = dev.get("device")
        for p in dev.get("ports", []):
            port = str(p.get("port"))
            key = (did, port)
            host_ip = port_ip_map.get(key, "unknown")
            
            curr_pkts = int(p.get("packetsReceived", 0)) + int(p.get("packetsSent", 0))
            curr_bytes = int(p.get("bytesReceived", 0)) + int(p.get("bytesSent", 0))

            prev_pkts, prev_bytes = collect._prev.get(key, (curr_pkts, curr_bytes))
            pkt_rate = max(curr_pkts - prev_pkts, 0) / dt
            byte_rate = max(curr_bytes - prev_bytes, 0) / dt

            collect._prev[key] = (curr_pkts, curr_bytes)
            
            # [3-TIER] Categorize traffic
            if host_ip and host_ip not in INFRA_IPS and host_ip != "unknown":
                # This is an attacker/host port - count as RAW incoming
                raw_incoming_packets += pkt_rate
                raw_incoming_bytes += byte_rate
            
            if key == web_port_key:
                # This is the web server port - count as EFFECTIVE traffic
                effective_packets += pkt_rate
                effective_bytes += byte_rate
                print(f"[COLLECTOR] Web1 port {key}: {pkt_rate:.1f} pps, {byte_rate/1024:.1f} KB/s")
            
            rows.append(
                {
                    "device_id": did,
                    "port": port,
                    "host_ip": host_ip,
                    "packets_total": curr_pkts,
                    "bytes_total": curr_bytes,
                    "packet_rate": round(pkt_rate, 2),
                    "byte_rate": round(byte_rate, 2),
                    "flow_count_device": flow_count_by_device.get(did, 0),
                    "is_web_port": key == web_port_key,
                    "is_attacker": host_ip and host_ip not in INFRA_IPS and host_ip != "unknown",
                }
            )

    collect._prev_time = now

    # [NEW] Collect DROP and RATE_LIMIT flow statistics
    import json
    import os

    # Load attack registry from IDS (if exists)
    attack_registry = {}
    registry_file = os.path.join(OUT_DIR, "attack_registry.json")
    if os.path.exists(registry_file):
        try:
            with open(registry_file, 'r') as f:
                attack_registry = json.load(f)
        except:
            pass

    drop_ips_data = []
    rate_limit_ips_data = []
    dropped_packets_total = 0
    dropped_bytes_total = 0
    rate_limited_packets_total = 0
    rate_limited_bytes_total = 0

    for flow in flows:
        treatment = flow.get("treatment", {})
        instructions = treatment.get("instructions", [])
        selector = flow.get("selector", {})
        criteria = selector.get("criteria", [])

        # Get source IP
        src_ip = None
        for c in criteria:
            if c.get("type") == "IPV4_SRC":
                src_ip = c.get("ip", "").replace("/32", "")
                break

        if not src_ip:
            continue

        packets = int(flow.get("packets", 0))
        bytes_cnt = int(flow.get("bytes", 0))

        # Determine flow type based on instructions
        if not instructions:
            # DROP flow - empty instructions
            dropped_packets_total += packets
            dropped_bytes_total += bytes_cnt
            attack_info = attack_registry.get(src_ip, {})
            drop_ips_data.append({
                "ip": src_ip,
                "packets": packets,
                "bytes": bytes_cnt,
                "priority": flow.get("priority", 0),
                "timeout": flow.get("timeout", 0),
                "state": "DROP",
                "attack_type": attack_info.get("attack_type", "UNKNOWN"),
                "confidence": attack_info.get("confidence", 0),
                "timestamp": attack_info.get("timestamp", 0)
            })
        elif any(inst.get("type") == "METER" for inst in instructions):
            # RATE_LIMIT flow - has METER instruction
            rate_limited_packets_total += packets
            rate_limited_bytes_total += bytes_cnt
            attack_info = attack_registry.get(src_ip, {})
            rate_limit_ips_data.append({
                "ip": src_ip,
                "packets": packets,
                "bytes": bytes_cnt,
                "priority": flow.get("priority", 0),
                "timeout": flow.get("timeout", 0),
                "state": "RATE_LIMIT",
                "attack_type": attack_info.get("attack_type", "UNKNOWN"),
                "confidence": attack_info.get("confidence", 0),
                "timestamp": attack_info.get("timestamp", 0)
            })

    # Calculate statistics
    total_blocks = len(drop_ips_data) + len(rate_limit_ips_data)
    drop_percentage = (len(drop_ips_data) / total_blocks * 100) if total_blocks > 0 else 0
    rate_limit_percentage = (len(rate_limit_ips_data) / total_blocks * 100) if total_blocks > 0 else 0

    # [3-TIER] Calculate derived metrics
    mitigated_packets = dropped_packets_total + rate_limited_packets_total
    mitigated_bytes = dropped_bytes_total + rate_limited_bytes_total
    
    # Protection efficiency
    protection_ratio = 0.0
    if raw_incoming_packets > 0:
        protection_ratio = (mitigated_packets / raw_incoming_packets) * 100
    
    return {
        "timestamp": now,
        "ports": rows,
        "blocked_ips": drop_ips_data + rate_limit_ips_data,
        "drop_ips": drop_ips_data,
        "rate_limit_ips": rate_limit_ips_data,
        "dropped_packets_total": dropped_packets_total,
        "dropped_bytes_total": dropped_bytes_total,
        "rate_limited_packets_total": rate_limited_packets_total,
        "rate_limited_bytes_total": rate_limited_bytes_total,
        "active_blocks": total_blocks,
        "drop_count": len(drop_ips_data),
        "rate_limit_count": len(rate_limit_ips_data),
        "drop_percentage": round(drop_percentage, 1),
        "rate_limit_percentage": round(rate_limit_percentage, 1),
        # [3-TIER] New traffic metrics
        "raw_incoming_packets_per_sec": round(raw_incoming_packets, 2),
        "raw_incoming_bytes_per_sec": round(raw_incoming_bytes, 2),
        "raw_incoming_mbps": round(raw_incoming_bytes * 8 / 1_000_000, 3),
        "effective_packets_per_sec": round(effective_packets, 2),
        "effective_bytes_per_sec": round(effective_bytes, 2),
        "effective_mbps": round(effective_bytes * 8 / 1_000_000, 3),
        "mitigated_packets_per_sec": round(mitigated_packets, 2),
        "mitigated_bytes_per_sec": round(mitigated_bytes, 2),
        "mitigated_mbps": round(mitigated_bytes * 8 / 1_000_000, 3),
        "protection_ratio_percent": round(protection_ratio, 1),
        "web_server_connected": web_port_key is not None,
        "web_port_location": web_port_key,
    }


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"[COLLECTOR] Starting ONOS metrics collection to {OUT_FILE}...")
    while True:
        try:
            data = collect()
            if data:
                with open(OUT_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            else:
                # If collection failed (e.g. ONOS down), don't overwrite with error immediately
                # unless it persists.
                pass
        except Exception as e:
            # Only write error if we haven't written success for a while
            print(f"[COLLECTOR] Error: {e}")
            time.sleep(5) # Wait longer on error
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
