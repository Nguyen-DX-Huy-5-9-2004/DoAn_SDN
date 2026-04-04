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


def get_json(path):
    # Reduced timeout to avoid blocking too long, let loop handle retry
    r = requests.get(f"{ONOS_BASE}/{path}", auth=AUTH, timeout=3)
    r.raise_for_status()
    return r.json()


def build_host_port_map(hosts):
    port_map = {}
    for host in hosts:
        ips = host.get("ipAddresses", [])
        locations = host.get("locations", [])
        for loc in locations:
            element = loc.get("elementId")
            port = str(loc.get("port"))
            if element and port and ips:
                port_map[(element, port)] = ips[0]
    return port_map


def collect():
    try:
        hosts = get_json("hosts").get("hosts", [])
        stats = get_json("statistics/ports").get("statistics", [])
        flows = get_json("flows").get("flows", [])
    except Exception as e:
        print(f"[COLLECTOR] ONOS Error: {e}")
        return None

    port_ip_map = build_host_port_map(hosts)

    flow_count_by_device = defaultdict(int)
    for flow in flows:
        did = flow.get("deviceId")
        if did:
            flow_count_by_device[did] += 1

    now = time.time()
    if not hasattr(collect, "_prev"):
        collect._prev = {}
        collect._prev_time = now

    dt = max(now - collect._prev_time, 0.001)
    rows = []
    for dev in stats:
        did = dev.get("device")
        for p in dev.get("ports", []):
            port = str(p.get("port"))
            key = (did, port)
            curr_pkts = int(p.get("packetsReceived", 0)) + int(p.get("packetsSent", 0))
            curr_bytes = int(p.get("bytesReceived", 0)) + int(p.get("bytesSent", 0))

            prev_pkts, prev_bytes = collect._prev.get(key, (curr_pkts, curr_bytes))
            pkt_rate = max(curr_pkts - prev_pkts, 0) / dt
            byte_rate = max(curr_bytes - prev_bytes, 0) / dt

            collect._prev[key] = (curr_pkts, curr_bytes)
            rows.append(
                {
                    "device_id": did,
                    "port": port,
                    "host_ip": port_ip_map.get(key, "unknown"),
                    "packets_total": curr_pkts,
                    "bytes_total": curr_bytes,
                    "packet_rate": round(pkt_rate, 2),
                    "byte_rate": round(byte_rate, 2),
                    "flow_count_device": flow_count_by_device.get(did, 0),
                }
            )

    collect._prev_time = now
    return {"timestamp": now, "ports": rows}


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
