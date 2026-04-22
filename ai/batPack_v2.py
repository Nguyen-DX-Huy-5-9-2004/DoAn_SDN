#!/usr/bin/env python3
"""
Tên file: batPack_v2.py
Phiên bản: 2.0 (Nâng cấp batPack123 cho production)

Mô tả:
  NFStreamer-based flow extractor tối ưu cho AI v2
  - Dual FIFO support (normal + slowloris phases)
  - Marker-based phase detection
  - Health check + auto-restart
  - Production-ready logging
  - Optimized batch flushing

Yêu cầu: pip install nfstream requests
"""

import errno
import json
import os
import time
import socket
import subprocess
import requests
import logging
from nfstream import NFStreamer
from datetime import datetime

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# =====================================================================
# LOGGING SETUP (Production)
# =====================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler('logs/batpack_v2.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =====================================================================
# CONFIGURATION (UNIFIED FOR NORMAL + SLOWLORIS)
# =====================================================================
class BatPackConfig:
    """Tập hợp cấu hình cho batPack_v2"""
    
    # Interface detection
    IFACE = os.environ.get("BATPACK_IFACE", "")
    
    # Output FIFO paths (dual mode)
    OUTPUT_FIFO_NORMAL = os.path.join(BASE_DIR, "zeek_stream.json")
    OUTPUT_FIFO_SLOWLORIS = os.path.join(BASE_DIR, "zeek_stream_slowloris.json")
    
    # Batch flushing
    FLUSH_BATCH_SIZE = 50  # Xả lũ sau mỗi 50 luồng
    FLUSH_INTERVAL = 1.0   # Hoặc sau mỗi 1 giây
    
    # Restricted ports (SDN control)
    RESTRICTED_PORTS = {22, 6633, 6653, 8181}
    
    # Slowloris health check (production)
    SLOWLORIS_HEALTH_URL = os.environ.get("SLOWLORIS_TARGET_URL", "http://127.0.0.1:8000")
    SLOWLORIS_CHECK_INTERVAL = 10.0  # Check every 10 seconds
    
    # Web restart command (if target dies)
    WEB_RESTART_CMD = os.environ.get("WEB_RESTART_CMD", "").strip()
    
    # Logging
    LOG_LEVEL = os.environ.get("BATPACK_LOG_LEVEL", "INFO")
    
    # NFStreamer optimization
    ACTIVE_TIMEOUT = 1    # Close flows after 1 second of inactivity
    IDLE_TIMEOUT = 1      # More aggressive for flood detection
    
    @classmethod
    def validate(cls):
        """Validate configuration at startup"""
        logger.info(f"[CONFIG] IFACE: {cls.IFACE or 'auto-detect'}")
        logger.info(f"[CONFIG] Output FIFOs: {cls.OUTPUT_FIFO_NORMAL} + {cls.OUTPUT_FIFO_SLOWLORIS}")
        logger.info(f"[CONFIG] Batch size: {cls.FLUSH_BATCH_SIZE}, Interval: {cls.FLUSH_INTERVAL}s")

# =====================================================================
# UTILITY FUNCTIONS
# =====================================================================

def pick_attribute(flow, *names, default=0):
    """Try multiple attribute names, return first available"""
    for name in names:
        if hasattr(flow, name):
            value = getattr(flow, name)
            if value is not None:
                return value
    return default

def detect_interface():
    """Auto-detect optimal capture interface"""
    if BatPackConfig.IFACE:
        logger.info(f"[IFACE] Using configured: {BatPackConfig.IFACE}")
        return BatPackConfig.IFACE
    
    try:
        nets = set(os.listdir("/sys/class/net"))
    except Exception as e:
        logger.warning(f"[IFACE] Failed to list interfaces: {e}")
        nets = set()
    
    # Prefer s6-eth1 (L3 backbone with 99.7% filter pass)
    preferred = ["s6-eth1", "s6-eth4", "h82-eth1", "s6-eth2", "s6-eth3"]
    
    for iface in preferred:
        if iface in nets:
            logger.info(f"[IFACE] Auto-detected optimal: {iface}")
            return iface
    
    # Fallback: any s6-eth*
    for iface in sorted(nets):
        if iface.startswith("s6-eth"):
            logger.info(f"[IFACE] Fallback: {iface}")
            return iface
    
    default = "s6-eth1"
    logger.warning(f"[IFACE] No interface found, using default: {default}")
    return default

def parse_target_url(raw_target):
    """Parse URL to (host, port)"""
    parsed = raw_target.replace("http://", "").replace("https://", "").split("/")[0]
    
    if ":" in parsed:
        host, port_str = parsed.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443 if raw_target.startswith("https://") else 80
    else:
        host = parsed
        port = 443 if raw_target.startswith("https://") else 80
    
    return host, port

def is_target_alive(host, port, timeout=5):
    """Health check: target server responding?"""
    try:
        url = f"http://{host}:{port}/"
        response = requests.get(url, timeout=timeout)
        return response.status_code in [200, 301, 302]
    except Exception as e:
        logger.debug(f"[HEALTH] {host}:{port} check failed: {e}")
        return False

def restart_webserver():
    """Execute web restart command if configured"""
    if not BatPackConfig.WEB_RESTART_CMD:
        logger.warning("[WEB] WEB_RESTART_CMD not configured, cannot auto-restart")
        return False
    
    try:
        subprocess.run(
            BatPackConfig.WEB_RESTART_CMD,
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30
        )
        logger.info("[WEB] Auto-restart command executed, waiting 5s")
        time.sleep(5)
        return True
    except Exception as e:
        logger.error(f"[WEB] Restart failed: {e}")
        return False

def wait_for_target_alive(target_url, max_retry=3, interval=2):
    """Wait for target to come alive with retries"""
    host, port = parse_target_url(target_url)
    
    for attempt in range(1, max_retry + 1):
        logger.info(f"[HEALTH] Attempt {attempt}/{max_retry}: checking {host}:{port}")
        if is_target_alive(host, port):
            logger.info(f"[HEALTH] ✅ {host}:{port} is alive")
            return True
        time.sleep(interval)
    
    logger.error(f"[HEALTH] ❌ {host}:{port} not responding after {max_retry} attempts")
    
    # Prompt user to restart
    logger.error("[WEB] Please start web server with:")
    logger.error("      containernet> web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000 &'")
    input("[WEB] Press ENTER when web server is ready...")
    
    return wait_for_target_alive(target_url, max_retry=2, interval=2)

# =====================================================================
# FIFO & MARKER MANAGEMENT
# =====================================================================

def create_fifo_if_needed(fifo_path):
    """Create FIFO if not exists with proper permissions (mode 0o666)"""
    if not os.path.exists(fifo_path):
        try:
            os.mkfifo(fifo_path)
            os.chmod(fifo_path, 0o666)  # Allow both read/write for all users
            logger.info(f"[FIFO] Created with mode 0o666: {fifo_path}")
        except OSError as e:
            if e.errno != errno.EEXIST:
                logger.error(f"[FIFO] Failed to create {fifo_path}: {e}")
                raise
    else:
        # Ensure existing FIFO has correct permissions
        try:
            os.chmod(fifo_path, 0o666)
        except OSError as e:
            logger.warning(f"[FIFO] Could not chmod {fifo_path}: {e}")

def choose_fifo_mode():
    """Detect which FIFO mode to use based on markers"""
    marker_slowloris = os.path.join(BASE_DIR, ".marker_slowloris")
    marker_normal = os.path.join(BASE_DIR, ".marker_normal")
    
    if os.path.exists(marker_slowloris):
        return "SLOWLORIS", BatPackConfig.OUTPUT_FIFO_SLOWLORIS
    elif os.path.exists(marker_normal):
        return "NORMAL", BatPackConfig.OUTPUT_FIFO_NORMAL
    else:
        # Default to NORMAL if no marker is found (for real-time IDS mode)
        return "NORMAL", BatPackConfig.OUTPUT_FIFO_NORMAL

# =====================================================================
# FEATURE EXTRACTION (13 FEATURES FOR V2)
# =====================================================================

def extract_features(flow):
    """
    Extract 13 features from NFStreamer flow
    Matches AI v2 feature format exactly
    
    Output: [Src_Port, Dst_Port, Protocol, Duration_Sec,
             Src_Bytes, Dst_Bytes, Src_Packets, Dst_Packets,
             Conn_State, L7_App_Protocol, Packet_Rate, Byte_Rate, Anomaly_Score]
    """
    # Feature 1-2: Port numbers
    src_port = int(pick_attribute(flow, 'src_port', 'sport', default=0))
    dst_port = int(pick_attribute(flow, 'dst_port', 'dport', default=0))
    
    # Feature 3: Protocol (TCP=6, UDP=17, etc)
    protocol = int(pick_attribute(flow, 'protocol', default=0))
    
    # Feature 4: Duration (seconds)
    duration_ms = pick_attribute(flow, 'bidirectional_duration_ms', default=0.1)
    duration_sec = max(0.001, duration_ms / 1000.0)
    
    # Feature 5-6: Bytes
    src_bytes = int(pick_attribute(flow, 'src2dst_bytes', 'src_bytes', default=0))
    dst_bytes = int(pick_attribute(flow, 'dst2src_bytes', 'dst_bytes', default=0))
    
    # Feature 7-8: Packets
    src_packets = int(pick_attribute(flow, 'src2dst_packets', 'src_packets', default=0))
    dst_packets = int(pick_attribute(flow, 'dst2src_packets', 'dst_packets', default=0))
    
    # Feature 9: Connection state
    # TCP: 0=incomplete, 1=complete
    # UDP: 2=flow
    if protocol == 6:  # TCP
        conn_state = 1 if (src_packets > 0 and dst_packets > 0) else 0
    elif protocol == 17:  # UDP
        conn_state = 2
    else:
        conn_state = 0
    
    # Feature 10: L7 Application protocol (mapped to int)
    app_name = str(pick_attribute(flow, 'application_name', default='Unknown')).upper()
    l7_app_code = 0
    if "HTTP" in app_name or "WEB" in app_name:
        l7_app_code = 1
    elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name:
        l7_app_code = 2
    elif "DNS" in app_name:
        l7_app_code = 3
    elif "OPENFLOW" in app_name:
        l7_app_code = 5
    
    # Feature 11: Packet rate (packets/sec)
    packet_rate = round((src_packets + dst_packets) / duration_sec, 4)
    
    # Feature 12: Byte rate (bytes/sec)
    byte_rate = round((src_bytes + dst_bytes) / duration_sec, 4)
    
    # Feature 13: Anomaly score (0 if normal, 1 if one-way)
    is_one_way = 1 if (src_bytes > 0 and dst_bytes == 0) or (dst_bytes > 0 and src_bytes == 0) else 0
    anomaly_score = float(is_one_way)
    
    # Return as list (13 features)
    features = [
        src_port, dst_port, protocol, duration_sec,
        src_bytes, dst_bytes, src_packets, dst_packets,
        conn_state, l7_app_code, packet_rate, byte_rate, anomaly_score
    ]
    
    return features

# =====================================================================
# BATPACK CAPTURE ENGINE (MAIN LOOP)
# =====================================================================

class BatPackEngine:
    """Main data capture engine using NFStreamer"""
    
    def __init__(self):
        self.iface = detect_interface()
        self.stats = {
            'flows_processed': 0,
            'flows_output': 0,
            'last_flush': time.time()
        }
        logger.info("[ENGINE] BatPack v2 engine initialized")
    
    def capture_normal_and_attack(self):
        """Capture normal + attack phases (phases 0-3)"""
        logger.info("[MODE] Starting NORMAL/ATTACK phase capture")
        logger.info("[FIFO] Output: " + BatPackConfig.OUTPUT_FIFO_NORMAL)
        
        create_fifo_if_needed(BatPackConfig.OUTPUT_FIFO_NORMAL)
        
        try:
            with open(BatPackConfig.OUTPUT_FIFO_NORMAL, 'a') as fifo:
                self._stream_flows(fifo)
        except Exception as e:
            logger.error(f"[NORMAL] Error: {e}")
    
    def capture_slowloris(self):
        """Capture slowloris phase (phase 4) with health check"""
        logger.info("[MODE] Starting SLOWLORIS phase capture")
        logger.info("[FIFO] Output: " + BatPackConfig.OUTPUT_FIFO_SLOWLORIS)
        
        # Health check before starting
        if not wait_for_target_alive(BatPackConfig.SLOWLORIS_HEALTH_URL):
            logger.error("[SLOWLORIS] Target not alive, aborting capture")
            return
        
        create_fifo_if_needed(BatPackConfig.OUTPUT_FIFO_SLOWLORIS)
        
        try:
            last_health_check = time.time()
            
            with open(BatPackConfig.OUTPUT_FIFO_SLOWLORIS, 'a') as fifo:
                for json_line in self._stream_flows_generator(fifo):
                    # Periodic health check
                    now = time.time()
                    if now - last_health_check > BatPackConfig.SLOWLORIS_CHECK_INTERVAL:
                        if not is_target_alive(*parse_target_url(BatPackConfig.SLOWLORIS_HEALTH_URL)):
                            logger.error("[SLOWLORIS] Target died during capture!")
                            # Try to restart
                            if restart_webserver():
                                if wait_for_target_alive(BatPackConfig.SLOWLORIS_HEALTH_URL):
                                    last_health_check = now
                                    continue
                            else:
                                logger.error("[SLOWLORIS] Cannot recover, stopping capture")
                                break
                        last_health_check = now
        except Exception as e:
            logger.error(f"[SLOWLORIS] Error: {e}")
    
    def _stream_flows(self, fifo_handle):
        """Stream flows to FIFO (blocking write)"""
        for _ in self._stream_flows_generator(fifo_handle):
            pass
    
    def _stream_flows_generator(self, fifo_handle):
        """Generator to stream flows from NFStreamer"""
        logger.info(f"[STREAM] Starting on interface: {self.iface}")
        
        try:
            streamer = NFStreamer(
                source=self.iface,
                active_timeout=BatPackConfig.ACTIVE_TIMEOUT,
                idle_timeout=BatPackConfig.IDLE_TIMEOUT,
                statistical_analysis=True
            )
            
            batch_json = []
            last_flush = time.time()
            
            for flow in streamer:
                # Skip loopback and IPv6
                if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                    continue
                
                # Skip restricted ports
                if flow.src_port in BatPackConfig.RESTRICTED_PORTS or \
                   flow.dst_port in BatPackConfig.RESTRICTED_PORTS:
                    continue
                
                # Extract features (13 features)
                try:
                    features = extract_features(flow)
                except Exception as e:
                    logger.debug(f"[FEATURE] Extraction failed: {e}")
                    continue
                
                # Create JSON record
                json_record = {
                    "src_ip": flow.src_ip,
                    "features": features
                }
                
                json_line = json.dumps(json_record) + "\n"
                batch_json.append(json_line)
                self.stats['flows_processed'] += 1
                
                # Flush batch
                now = time.time()
                should_flush = (
                    len(batch_json) >= BatPackConfig.FLUSH_BATCH_SIZE or
                    (now - last_flush) >= BatPackConfig.FLUSH_INTERVAL
                )
                
                if should_flush and batch_json:
                    try:
                        fifo_handle.writelines(batch_json)
                        fifo_handle.flush()
                        self.stats['flows_output'] += len(batch_json)
                        
                        if self.stats['flows_output'] % 500 == 0:
                            logger.info(f"[STATS] Processed: {self.stats['flows_processed']}, Output: {self.stats['flows_output']}")
                        
                        batch_json.clear()
                        last_flush = now
                    except (BrokenPipeError, FileNotFoundError):
                        logger.warning("[FIFO] Pipe closed, waiting for reconnection...")
                        time.sleep(1)
                
                yield json_line
        
        except Exception as e:
            logger.error(f"[STREAM] Fatal error: {e}")

# =====================================================================
# MAIN ENTRY POINT
# =====================================================================

def main():
    """Main function with phase detection"""
    logger.info("=" * 70)
    logger.info("🚀 BatPack v2.0 - AI v2 Data Collection Engine")
    logger.info("=" * 70)
    
    # Validate config
    BatPackConfig.validate()
    
    # Create engine
    engine = BatPackEngine()
    
    # Infinite loop: monitor markers and capture accordingly
    while True:
        mode, fifo_path = choose_fifo_mode()
        
        if mode == "SLOWLORIS":
            engine.capture_slowloris()
        elif mode == "NORMAL":
            engine.capture_normal_and_attack()
        else:
            logger.info("[WAIT] No marker found, waiting for generator signal...")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n[EXIT] Interrupted by user")
    except Exception as e:
        logger.critical(f"[FATAL] Unhandled error: {e}", exc_info=True)
