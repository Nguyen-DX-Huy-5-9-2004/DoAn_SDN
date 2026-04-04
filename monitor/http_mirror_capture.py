import csv
import os
import time
from datetime import datetime

from scapy.all import IP, TCP, Raw, sniff


OUTPUT_DIR = "monitor/runtime"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "http_requests.csv")
MIRROR_IFACE = os.environ.get("MIRROR_IFACE", "h82-eth1")
MAX_LOG_LINES = 1000

# To correlate requests and responses
pending_requests = {}

def ensure_output():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not os.path.exists(OUTPUT_CSV):
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "method", "url", "payload_len", "status_code", "user_agent"])

def rotate_log():
    """Limit the number of lines in the CSV log file."""
    if not os.path.exists(OUTPUT_CSV):
        return
    try:
        with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > MAX_LOG_LINES:
            header = lines[0]
            # Keep last N lines
            kept_lines = [header] + lines[-(MAX_LOG_LINES-1):]
            with open(OUTPUT_CSV, "w", encoding="utf-8") as f:
                f.writelines(kept_lines)
    except Exception as e:
        print(f"[CAPTURE] Rotation error: {e}")

def parse_http_request(raw_bytes):
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        if not lines: return None
        first_line = lines[0]
        parts = first_line.split()
        if len(parts) >= 2 and parts[0] in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            user_agent = "unknown"
            for line in lines[1:]:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                    break
            return parts[0], parts[1], len(raw_bytes), user_agent
    except Exception:
        return None
    return None

def parse_http_response(raw_bytes):
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        if not lines: return None
        first_line = lines[0]
        # Example: HTTP/1.1 200 OK
        if first_line.startswith("HTTP/"):
            parts = first_line.split()
            if len(parts) >= 2:
                return parts[1] # Status code
    except Exception:
        return None
    return None

def handle_packet(pkt):
    if IP not in pkt or TCP not in pkt or Raw not in pkt:
        return
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    raw_payload = bytes(pkt[Raw].load)

    # Request to web1 (dst port 80)
    if dport == 80:
        parsed = parse_http_request(raw_payload)
        if parsed:
            method, url, payload_len, ua = parsed
            ts = datetime.utcnow().isoformat()
            session_key = (src_ip, sport, dst_ip, dport)
            pending_requests[session_key] = {
                "ts": ts, "src": src_ip, "method": method, "url": url, "len": payload_len, "ua": ua
            }
            
    # Response from web1 (src port 80)
    elif sport == 80:
        status_code = parse_http_response(raw_payload)
        if status_code:
            session_key = (dst_ip, dport, src_ip, sport) # Flip key to match request
            req = pending_requests.pop(session_key, None)
            if req:
                with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([req["ts"], req["src"], req["method"], req["url"], req["len"], status_code, req["ua"]])
                rotate_log()
            else:
                # Log response even if request wasn't seen (rare but possible with long sessions)
                ts = datetime.utcnow().isoformat()
                with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([ts, src_ip, "RES", "-", len(raw_payload), status_code, "unknown"])
                rotate_log()


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
