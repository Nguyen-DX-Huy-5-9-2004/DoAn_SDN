import csv
import os
import time
from datetime import datetime

from scapy.all import IP, TCP, Raw, sniff


OUTPUT_DIR = "monitor/runtime"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "http_requests.csv")
MIRROR_IFACE = os.environ.get("MIRROR_IFACE", "h82-eth1")


def ensure_output():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not os.path.exists(OUTPUT_CSV):
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "method", "url", "payload_len"])


def parse_http(raw_bytes):
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        first_line = text.splitlines()[0] if text else ""
        parts = first_line.split()
        if len(parts) >= 2 and parts[0] in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            return parts[0], parts[1], len(raw_bytes)
    except Exception:
        return None
    return None


def handle_packet(pkt):
    if IP not in pkt or TCP not in pkt or Raw not in pkt:
        return
    if pkt[TCP].dport != 80 and pkt[TCP].sport != 80:
        return

    parsed = parse_http(bytes(pkt[Raw].load))
    if not parsed:
        return

    method, url, payload_len = parsed
    src_ip = pkt[IP].src
    ts = datetime.utcnow().isoformat()

    with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([ts, src_ip, method, url, payload_len])


if __name__ == "__main__":
    ensure_output()
    print(f"[CAPTURE] Writing mirrored HTTP logs to {OUTPUT_CSV} (iface={MIRROR_IFACE})")
    while True:
        try:
            sniff(
                iface=MIRROR_IFACE,
                filter="tcp port 80",
                prn=handle_packet,
                store=False,
                timeout=15,
            )
        except Exception:
            time.sleep(1)
