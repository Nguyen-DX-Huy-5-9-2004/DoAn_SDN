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
import threading
import queue
from nfstream import NFStreamer
from datetime import datetime
from requests.auth import HTTPBasicAuth

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
# UNIFIED METRICS CONFIG (for Dashboard)
# =====================================================================
UNIFIED_METRICS_DIR = os.path.join(BASE_DIR, "..", "monitor", "runtime")
UNIFIED_METRICS_FILE = os.path.join(UNIFIED_METRICS_DIR, "unified_metrics.json")

# ONOS REST API Config (for dashboard metrics)
ONOS_URL = os.environ.get("ONOS_URL", "http://127.0.0.1:8181/onos/v1")
ONOS_AUTH = HTTPBasicAuth(
    os.environ.get("ONOS_USER", "onos"),
    os.environ.get("ONOS_PASS", "rocks")
)
METRICS_INTERVAL = 2.0  # seconds

# Protected infrastructure IPs
INFRA_IPS = {"10.0.0.10", "10.0.0.11", "10.0.0.20"}
PROXY_IP = "10.0.0.10"  # Nginx Proxy
WEB_SERVER_IP = "10.0.0.11"  # Backend Django
# Track traffic to both proxy and web server for complete monitoring
TARGET_IPS = {PROXY_IP, WEB_SERVER_IP}

# =====================================================================
# CONFIGURATION (UNIFIED FOR NORMAL + SLOWLORIS)
# =====================================================================
class BatPackConfig:
    """Tập hợp cấu hình cho batPack_v2"""
    
    # Interface detection
    IFACE = os.environ.get("BATPACK_IFACE", "")
    
    # Output FIFO paths (dual mode) - for AI
    OUTPUT_FIFO_NORMAL = os.path.join(BASE_DIR, "zeek_stream.json")
    OUTPUT_FIFO_SLOWLORIS = os.path.join(BASE_DIR, "zeek_stream_slowloris.json")
    
    # Output JSON path - for Dashboard (unified metrics)
    UNIFIED_METRICS_FILE = os.path.join(BASE_DIR, "..", "monitor", "runtime", "unified_metrics.json")
    
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
    
    # NFStreamer optimization - Default (Normal mode)
    ACTIVE_TIMEOUT = 10   # Tăng lên 10s để không chặt nhỏ luồng người dùng Keep-alive
    IDLE_TIMEOUT = 5      # Để 5s nhàn rỗi mới đóng luồng (giúp bắt được sự ngắt quãng tự nhiên)
    
    # Attack-specific tuning profiles
    TIMEOUT_PROFILES = {
        "NORMAL": {
            "ACTIVE_TIMEOUT": 3,  # Giảm từ 10s để bắt flows nhanh hơn
            "IDLE_TIMEOUT": 2,    # Giảm từ 5s cho flows ngắn
            "desc": "Normal: Standard bidirectional flows (fast capture)"
        },
        "UDP": {
            "ACTIVE_TIMEOUT": 3,     # UDP is unidirectional, close quickly
            "IDLE_TIMEOUT": 1,       # One-way packets don't have response
            "desc": "UDP Flood: Fast flow closure (unidirectional)"
        },
        "SYN": {
            "ACTIVE_TIMEOUT": 5,     # SYN packets, incomplete handshake
            "IDLE_TIMEOUT": 2,       # Half-open connections
            "desc": "SYN Flood: Capture half-open connections"
        },
        "HTTP": {
            "ACTIVE_TIMEOUT": 8,     # HTTP requests, connection pooling
            "IDLE_TIMEOUT": 3,       # Wait for HTTP response
            "desc": "HTTP Flood: Sustained HTTP requests"
        },
        "SLOWLORIS": {
            "ACTIVE_TIMEOUT": 30,    # Slowloris keeps connections alive very long
            "IDLE_TIMEOUT": 15,      # Long idle periods with keep-alive
            "desc": "Slowloris: Long-lived slow connections"
        }
    }
    
    @classmethod
    def get_profile(cls):
        """Detect current phase and return appropriate timeout profile"""
        markers_dir = BASE_DIR
        
        # Check for phase-specific markers (new granular approach)
        marker_slowloris = os.path.join(markers_dir, ".marker_slowloris")
        marker_http = os.path.join(markers_dir, ".marker_http")
        marker_syn = os.path.join(markers_dir, ".marker_syn")
        marker_udp = os.path.join(markers_dir, ".marker_udp")
        marker_normal = os.path.join(markers_dir, ".marker_normal")
        
        if os.path.exists(marker_slowloris):
            return cls.TIMEOUT_PROFILES["SLOWLORIS"]
        elif os.path.exists(marker_http):
            return cls.TIMEOUT_PROFILES["HTTP"]
        elif os.path.exists(marker_syn):
            return cls.TIMEOUT_PROFILES["SYN"]
        elif os.path.exists(marker_udp):
            return cls.TIMEOUT_PROFILES["UDP"]
        elif os.path.exists(marker_normal):
            return cls.TIMEOUT_PROFILES["NORMAL"]
        else:
            # Default to NORMAL if no marker is found (for real-time IDS mode)
            return cls.TIMEOUT_PROFILES["NORMAL"]
    
    @classmethod
    def validate(cls):
        """Validate configuration at startup"""
        profile = cls.get_profile()
        logger.info(f"[CONFIG] IFACE: {cls.IFACE or 'auto-detect'}")
        logger.info(f"[CONFIG] Output FIFOs: {cls.OUTPUT_FIFO_NORMAL} + {cls.OUTPUT_FIFO_SLOWLORIS}")
        logger.info(f"[CONFIG] Batch size: {cls.FLUSH_BATCH_SIZE}, Interval: {cls.FLUSH_INTERVAL}s")
        logger.info(f"[CONFIG] Timeout Profile: {profile['desc']}")
        logger.info(f"[CONFIG] ACTIVE_TIMEOUT={profile['ACTIVE_TIMEOUT']}s, IDLE_TIMEOUT={profile['IDLE_TIMEOUT']}s")

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
    logger.error("      containernet> web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000&'")
    input("[WEB] Press ENTER when web server is ready...")
    
    return wait_for_target_alive(target_url, max_retry=2, interval=2)


# =====================================================================
# NFSTREAMER FLOW STATS TRACKER (Dashboard Support - Web1 Focused)
# =====================================================================

class FlowStatsTracker:
    """
    Track NFStreamer flows in real-time for dashboard metrics.
    Receives flow data directly from BatPackEngine (same as AI).
    Only tracks flows to WEB_SERVER_IP (10.0.0.11).
    """
    
    def __init__(self, interval=METRICS_INTERVAL):
        self.interval = interval
        self.running = False
        self.thread = None
        self._lock = threading.Lock()
        
        # Real-time flow statistics
        self._flow_stats = {
            "total_flows_seen": 0,
            "web1_flows_seen": 0,
            "src_ips": {},  # {ip: {packets, bytes, last_seen}}
            "blocked_ips": set(),  # IPs detected as malicious by AI
            "raw_bytes_total": 0,
            "raw_packets_total": 0,
        }
        
        self._latest_metrics = {}
        logger.info("[FLOW-TRACKER] Initialized for web1-focused metrics")
    
    def record_flow(self, src_ip, dst_ip, src_port, dst_port, packets, bytes_cnt, protocol):
        """Called by BatPackEngine for each captured flow"""
        with self._lock:
            self._flow_stats["total_flows_seen"] += 1
            # Debug log for target-bound flows (proxy or web1)
            if dst_ip in TARGET_IPS and self._flow_stats["total_flows_seen"] <= 10:
                target_type = "proxy" if dst_ip == PROXY_IP else "web1"
                logger.info(f"[FLOW-TRACKER] Tracked flow to {target_type}: {src_ip} -> {dst_ip}:{dst_port} "
                          f"({packets} pkts, {bytes_cnt} bytes)")
            
            # Track flows TO proxy or web1 (both are part of the infrastructure)
            if dst_ip in TARGET_IPS:
                self._flow_stats["web1_flows_seen"] += 1
                self._flow_stats["raw_bytes_total"] += bytes_cnt
                self._flow_stats["raw_packets_total"] += packets
                
                # Track per-source IP stats
                if src_ip not in self._flow_stats["src_ips"]:
                    self._flow_stats["src_ips"][src_ip] = {
                        "packets": 0, "bytes": 0, "flow_count": 0,
                        "ports": set(), "first_seen": time.time(), "last_seen": time.time()
                    }
                
                ip_stat = self._flow_stats["src_ips"][src_ip]
                ip_stat["packets"] += packets
                ip_stat["bytes"] += bytes_cnt
                ip_stat["flow_count"] += 1
                ip_stat["ports"].add(dst_port)
                ip_stat["last_seen"] = time.time()
    
    def get_top_talkers(self, n=10):
        """Get top N IPs by traffic to web1.
        NOTE: Must be called from within self._lock to avoid deadlock!"""
        # [FIX] Simplified to avoid blocking on large datasets
        src_ips = self._flow_stats["src_ips"]
        logger.info(f"[get_top_talkers] Processing {len(src_ips)} unique IPs")
        
        # Use nlargest from heapq for better performance on large datasets
        import heapq
        top_n = heapq.nlargest(
            n, 
            src_ips.items(), 
            key=lambda x: x[1]["bytes"]
        )
        
        result = []
        for ip, stats in top_n:
            result.append({
                "ip": ip,
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "flow_count": stats["flow_count"],
                "ports": list(stats["ports"]),
                "blocked": ip in self._flow_stats["blocked_ips"]
            })
        
        logger.info(f"[get_top_talkers] Returning {len(result)} top talkers")
        return result
    
    def query_onos_mitigation_stats(self):
        """Query ONOS for actual DROP/RATE_LIMIT flows (mitigation results)"""
        try:
            # Get flows from ONOS
            r = requests.get(f"{ONOS_URL}/flows", auth=ONOS_AUTH, timeout=3)
            r.raise_for_status()
            flows = r.json().get("flows", [])
            
            drop_ips = []
            rate_limit_ips = []
            dropped_packets = 0
            dropped_bytes = 0
            rate_limited_packets = 0
            rate_limited_bytes = 0
            
            for flow in flows:
                treatment = flow.get("treatment", {})
                instructions = treatment.get("instructions", [])
                selector = flow.get("selector", {})
                criteria = selector.get("criteria", [])
                
                # Get src IP
                src_ip = None
                for c in criteria:
                    if c.get("type") == "IPV4_SRC":
                        src_ip = c.get("ip", "").replace("/32", "")
                        break
                
                if not src_ip:
                    continue
                
                packets = int(flow.get("packets", 0))
                bytes_cnt = int(flow.get("bytes", 0))
                
                # [FIX] Removed src_ips check - always show blocked IPs from ONOS
                # The IP might have been detected in previous window
                
                if not instructions:
                    # DROP flow
                    dropped_packets += packets
                    dropped_bytes += bytes_cnt
                    drop_ips.append({"ip": src_ip, "packets": packets, "bytes": bytes_cnt, "state": "DROP"})
                    self._flow_stats["blocked_ips"].add(src_ip)
                elif any(inst.get("type") == "METER" for inst in instructions):
                    # RATE_LIMIT flow
                    rate_limited_packets += packets
                    rate_limited_bytes += bytes_cnt
                    rate_limit_ips.append({"ip": src_ip, "packets": packets, "bytes": bytes_cnt, "state": "RATE_LIMIT"})
                    self._flow_stats["blocked_ips"].add(src_ip)
            
            return {
                "drop_ips": drop_ips,
                "rate_limit_ips": rate_limit_ips,
                "dropped_packets_total": dropped_packets,
                "dropped_bytes_total": dropped_bytes,
                "rate_limited_packets_total": rate_limited_packets,
                "rate_limited_bytes_total": rate_limited_bytes,
                "active_blocks": len(drop_ips) + len(rate_limit_ips)
            }
            
        except Exception as e:
            logger.debug(f"[FLOW-TRACKER] ONOS query error: {e}")
            return {
                "drop_ips": [], "rate_limit_ips": [],
                "dropped_packets_total": 0, "dropped_bytes_total": 0,
                "rate_limited_packets_total": 0, "rate_limited_bytes_total": 0,
                "active_blocks": 0
            }
    
    def build_metrics(self):
        """Build unified metrics for dashboard"""
        # logger.info("[build_metrics] Acquiring lock...")  # Reduced verbosity
        with self._lock:
            # logger.info("[build_metrics] Lock acquired")  # Reduced verbosity
            now = time.time()
            
            # Get mitigation stats from ONOS
            # logger.info("[build_metrics] Calling query_onos_mitigation_stats()...")  # Reduced verbosity
            mitigation = self.query_onos_mitigation_stats()
            # logger.info(f"[build_metrics] query_onos_mitigation_stats() done: {mitigation}")  # Reduced verbosity
            
            # Calculate 3-tier metrics based on NFStreamer data
            # logger.info("[build_metrics] Calculating metrics...")  # Reduced verbosity
            raw_bytes = self._flow_stats["raw_bytes_total"]
            raw_packets = self._flow_stats["raw_packets_total"]
            # logger.info(f"[build_metrics] raw_bytes={raw_bytes}, raw_packets={raw_packets}")  # Reduced verbosity
            
            # Estimate rates (since we track cumulative, need recent window)
            # For simplicity, assume metrics interval is the window
            # logger.info("[build_metrics] Computing raw_mbps...")  # Reduced verbosity
            raw_mbps = (raw_bytes * 8 / 1_000_000) / max(self.interval, 1)
            # logger.info(f"[build_metrics] raw_mbps={raw_mbps}")  # Reduced verbosity
            
            # Mitigated = traffic from blocked IPs
            # logger.info("[build_metrics] Computing mitigated_bytes...")  # Reduced verbosity
            mitigated_bytes = sum(
                self._flow_stats["src_ips"][ip]["bytes"]
                for ip in self._flow_stats["blocked_ips"]
                if ip in self._flow_stats["src_ips"]
            )
            # logger.info(f"[build_metrics] mitigated_bytes={mitigated_bytes}")  # Reduced verbosity
            mitigated_mbps = (mitigated_bytes * 8 / 1_000_000) / max(self.interval, 1)
            
            # Effective = raw - mitigated
            effective_mbps = max(raw_mbps - mitigated_mbps, 0)
            
            # Protection ratio
            protection_ratio = 0.0
            if raw_mbps > 0:
                protection_ratio = (mitigated_mbps / raw_mbps) * 100
            
            # Build port-like rows for dashboard compatibility - include all hosts h1-h20 and h60-h65
            rows = []
            
            # Define expected hosts
            expected_hosts = []
            for i in range(1, 21):  # h1-h20
                expected_hosts.append(f"10.0.1.{i}")
            for i in range(60, 66):  # h60-h65
                expected_hosts.append(f"10.0.2.{i}")
            
            # Add data for each expected host
            for host_ip in expected_hosts:
                if host_ip in self._flow_stats["src_ips"]:
                    stats = self._flow_stats["src_ips"][host_ip]
                    rows.append({
                        "device_id": "nfstream",
                        "port": host_ip.split(".")[-1],  # Use last octet as port
                        "host_ip": host_ip,
                        "packet_rate": round(stats["packets"] / max(self.interval, 1), 2),
                        "byte_rate": round(stats["bytes"] / max(self.interval, 1), 2),
                        "is_web_port": True,
                        "blocked": host_ip in self._flow_stats["blocked_ips"]
                    })
                else:
                    # Add empty entry for hosts with no traffic
                    rows.append({
                        "device_id": "nfstream",
                        "port": host_ip.split(".")[-1],
                        "host_ip": host_ip,
                        "packet_rate": 0.0,
                        "byte_rate": 0.0,
                        "is_web_port": True,
                        "blocked": False
                    })
            
            metrics = {
                "timestamp": now,
                "status": "online",
                "onos_online": True,
                "source": "nfstream",  # Mark as NFStreamer data
                "ports": rows,
                "flow_count": self._flow_stats["web1_flows_seen"],
                **mitigation,
                # 3-tier metrics from NFStreamer (web1-focused)
                "raw_incoming_mbps": round(raw_mbps, 3),
                "effective_mbps": round(effective_mbps, 3),
                "mitigated_mbps": round(mitigated_mbps, 3),
                "protection_ratio_percent": round(min(protection_ratio, 100.0), 1),
                "web_server_connected": self._flow_stats["web1_flows_seen"] > 0,
                "total_flows_processed": self._flow_stats["total_flows_seen"],
                "unique_src_ips": len(self._flow_stats["src_ips"])
            }
            
            # logger.info(f"[build_metrics] Done! Returning metrics with flow_count={metrics.get('flow_count')}")  # Reduced load during attacks
            return metrics
    
    def reset_window_stats(self):
        """Reset per-window stats after writing metrics"""
        with self._lock:
            # Keep cumulative blocked_ips, reset counters
            self._flow_stats["raw_bytes_total"] = 0
            self._flow_stats["raw_packets_total"] = 0
            self._flow_stats["src_ips"] = {}
    
    def _collection_loop(self):
        """Background thread loop"""
        logger.info("[FLOW-TRACKER] Starting background metrics thread")
        logger.info(f"[FLOW-TRACKER] Writing to: {UNIFIED_METRICS_FILE}")
        
        loop_count = 0
        while self.running:
            loop_count += 1
            if loop_count <= 3:  # Log first 3 iterations
                logger.info(f"[FLOW-TRACKER] Loop #{loop_count}, running={self.running}")
            
            try:
                # logger.info("[FLOW-TRACKER] Calling build_metrics()...")  # Reduced verbosity
                metrics = self.build_metrics()
                # logger.info(f"[FLOW-TRACKER] build_metrics() done, flow_count={metrics.get('flow_count')}")  # Reduced verbosity
                self._latest_metrics = metrics
                
                # logger.info("[FLOW-TRACKER] Creating directory...")  # Reduced verbosity
                os.makedirs(UNIFIED_METRICS_DIR, exist_ok=True)
                with open(UNIFIED_METRICS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(metrics, f)
                    f.flush()
                
                # Verify write
                import os as os_check
                file_size = os_check.path.getsize(UNIFIED_METRICS_FILE)
                # logger.info(f"[FLOW-TRACKER] Written {file_size} bytes: {metrics['flow_count']} flows, "
                #           f"{metrics['active_blocks']} blocks, "
                #           f"{metrics['raw_incoming_mbps']:.2f} Mbps raw, "
                #           f"{metrics['effective_mbps']:.2f} Mbps effective")  # Reduced load during attacks
                
                # Reset for next window
                self.reset_window_stats()
                
            except Exception as e:
                logger.error(f"[FLOW-TRACKER] Metrics error: {e}", exc_info=True)
            
            time.sleep(self.interval)
    
    def start(self):
        """Start background collection thread"""
        logger.info(f"[FLOW-TRACKER] start() called, running={self.running}")
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._collection_loop, daemon=True)
            self.thread.start()
            logger.info(f"[FLOW-TRACKER] Thread started, id={self.thread.ident}")
        else:
            logger.info("[FLOW-TRACKER] Already running, skipping start")
    
    def stop(self):
        """Stop background collection thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("[FLOW-TRACKER] Stopped")
    
    def get_latest(self):
        """Get latest collected metrics"""
        return self._latest_metrics


# Global tracker instance (shared with BatPackEngine)
flow_tracker = FlowStatsTracker(interval=METRICS_INTERVAL)


# =====================================================================
# FIFO & MARKER MANAGEMENT
# =====================================================================

def create_fifo_if_needed(fifo_path):
    """Create FIFO if not exists with proper permissions (mode 0o666)"""
    if not os.path.exists(fifo_path):
        try:
            os.mkfifo(fifo_path)
            os.chmod(fifo_path, 0o666)
            logger.info(f"[FIFO] Created: {fifo_path}")
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
    else:
        try:
            os.chmod(fifo_path, 0o666)
        except OSError:
            pass

def choose_fifo_mode():
    """Detect which FIFO mode and timeout profile to use based on markers"""
    # Check for phase-specific markers (new granular approach)
    marker_slowloris = os.path.join(BASE_DIR, ".marker_slowloris")
    marker_http = os.path.join(BASE_DIR, ".marker_http")
    marker_syn = os.path.join(BASE_DIR, ".marker_syn")
    marker_udp = os.path.join(BASE_DIR, ".marker_udp")
    marker_normal = os.path.join(BASE_DIR, ".marker_normal")
    
    profile = BatPackConfig.get_profile()
    
    if os.path.exists(marker_slowloris):
        mode = "SLOWLORIS"
        fifo_path = BatPackConfig.OUTPUT_FIFO_SLOWLORIS
    elif os.path.exists(marker_http) or os.path.exists(marker_syn) or os.path.exists(marker_udp) or os.path.exists(marker_normal):
        # All attack phases (UDP, SYN, HTTP) and normal use the same FIFO
        mode = "NORMAL"
        fifo_path = BatPackConfig.OUTPUT_FIFO_NORMAL
    else:
        # [FIX] Không có marker nào - đợi signal từ generator
        # Tránh tạo sai FIFO khi khởi động trước generator
        return None, None, None
    
    return mode, fifo_path, profile

# =====================================================================
# FEATURE EXTRACTION (13 FEATURES FOR V2)
# =====================================================================

# =====================================================================
# PORT ENTROPY CALCULATOR (NEW)
# =====================================================================
class PortEntropyCalculator:
    """Tính toán Entropy của cổng để phát hiện sự hỗn loạn của Botnet"""
    def __init__(self, window_size=10):
        self.window_size = window_size
        self.history = {} # {ip: [port1, port2, ...]}

    def update_and_calculate(self, ip, port):
        if ip not in self.history:
            self.history[ip] = []
        
        self.history[ip].append(port)
        if len(self.history[ip]) > self.window_size:
            self.history[ip].pop(0)
            
        # Tính toán Shannon Entropy
        from collections import Counter
        import math
        
        ports = self.history[ip]
        counts = Counter(ports)
        entropy = 0
        for count in counts.values():
            p = count / len(ports)
            entropy -= p * math.log2(p)
        return round(entropy, 4)

# Khởi tạo Global Calculator
port_entropy_engine = PortEntropyCalculator(window_size=10)

def extract_features(flow):
    """
    Extract 13 features from NFStreamer flow
    NÂNG CẤP: Sử dụng Port Entropy cho cả cổng nguồn và cổng đích.
    """
    # Lấy thông tin IP để tính Entropy
    src_ip = flow.src_ip
    dst_ip = flow.dst_ip
    
    # Feature 1: Src Port Entropy
    raw_src_port = int(pick_attribute(flow, 'src_port', 'sport', default=0))
    src_port_entropy = port_entropy_engine.update_and_calculate(src_ip, raw_src_port)

    # Feature 2: Dst Port Entropy
    raw_dst_port = int(pick_attribute(flow, 'dst_port', 'dport', default=0))
    dst_port_entropy = port_entropy_engine.update_and_calculate(dst_ip, raw_dst_port)

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
    if protocol == 6:  # TCP
        conn_state = 1 if (src_packets > 0 and dst_packets > 0) else 0
    elif protocol == 17:  # UDP
        conn_state = 2
    else:
        conn_state = 0
    
    # Feature 10: L7 Application protocol
    app_name = str(pick_attribute(flow, 'application_name', default='Unknown')).upper()
    l7_app_code = 0
    if "HTTP" in app_name or "WEB" in app_name: l7_app_code = 1
    elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name: l7_app_code = 2
    elif "DNS" in app_name: l7_app_code = 3
    elif "OPENFLOW" in app_name: l7_app_code = 5
    
    # Feature 11: Packet rate
    packet_rate = round((src_packets + dst_packets) / duration_sec, 4)
    
    # Feature 12: Byte rate
    byte_rate = round((src_bytes + dst_bytes) / duration_sec, 4)
    
    # Feature 13: Anomaly score
    is_one_way = 1 if (src_bytes > 0 and dst_bytes == 0) or (dst_bytes > 0 and src_bytes == 0) else 0
    anomaly_score = float(is_one_way)
    
    # Return as list (13 features)
    features = [
        src_port_entropy, dst_port_entropy, protocol, duration_sec,
        src_bytes, dst_bytes, src_packets, dst_packets,
        conn_state, l7_app_code, packet_rate, byte_rate, anomaly_score
    ]
    
    return features

def flow_export_key(flow) -> str:
    """
    Định danh ổn định cho mỗi bản ghi NFStream xuất ra FIFO.
    Giúp IDS bỏ qua khi cùng một flow được gửi lặp (batch/flush trùng).
    """
    fid = getattr(flow, "id", None)
    if fid is not None:
        try:
            return str(int(fid))
        except (TypeError, ValueError):
            return str(fid)
    fs = getattr(flow, "bidirectional_first_seen_ms", None)
    if fs is None:
        fs = getattr(flow, "first_seen_ms", 0) or 0
    sp = int(pick_attribute(flow, "src_port", "sport", default=0))
    dp = int(pick_attribute(flow, "dst_port", "dport", default=0))
    pr = int(pick_attribute(flow, "protocol", default=0))
    return f"{flow.src_ip}|{flow.dst_ip}|{sp}|{dp}|{pr}|{int(fs)}"

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
        """Capture normal + attack phases (phases 0-3)
        [DEMO MODE] Always capture for dashboard, try FIFO in background thread
        """
        logger.info("[MODE] Starting NORMAL/ATTACK phase capture")
        logger.info("[DEMO] Dashboard capture always active")
        logger.info("[DEMO] FIFO output (for AI): " + BatPackConfig.OUTPUT_FIFO_NORMAL)
        
        create_fifo_if_needed(BatPackConfig.OUTPUT_FIFO_NORMAL)
        
        # [DEMO MODE] Start FIFO writer thread (non-blocking for dashboard)
        # This allows batPack to run WITHOUT run_onos_v2 for Phase 1 demo
        fifo_queue = queue.Queue(maxsize=1000)
        fifo_thread = threading.Thread(
            target=self._fifo_writer_thread,
            args=(BatPackConfig.OUTPUT_FIFO_NORMAL, fifo_queue),
            daemon=True
        )
        fifo_thread.start()
        
        # Always capture for dashboard (main thread)
        logger.info("[CAPTURE] Starting dashboard metrics capture...")
        # Iterate through generator to actually run capture
        for _ in self._stream_flows_generator_with_fifo(fifo_queue):
            pass
    
    def _fifo_writer_thread(self, fifo_path, fifo_queue):
        """Background thread to write to FIFO - keeps retrying for demo mode"""
        logger.info("[FIFO-THREAD] Waiting for AI reader (run_onos_v2)...")
        
        import fcntl
        consecutive_errors = 0
        
        while True:  # Keep trying forever (for demo mode)
            # Wait for FIFO reader
            fifo_fd = None
            for attempt in range(120):  # Wait up to 120 seconds per attempt
                try:
                    fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
                    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
                    fifo_fd = fd
                    logger.info(f"[FIFO-THREAD] ✓ AI reader connected after {attempt}s")
                    break
                except (BlockingIOError, OSError):
                    time.sleep(1)
                    continue
                except Exception as e:
                    time.sleep(1)
                    continue
            
            if fifo_fd is None:
                logger.info("[FIFO-THREAD] No AI reader yet, retrying in 5s... (batPack still capturing for dashboard)")
                time.sleep(5)
                continue  # Retry loop
            
            # Write to FIFO
            try:
                with os.fdopen(fifo_fd, 'w') as fifo:
                    logger.info("[FIFO-THREAD] → Now forwarding flows to AI")
                    while True:
                        try:
                            json_line = fifo_queue.get(timeout=0.1)
                            fifo.write(json_line)
                            fifo.flush()
                            consecutive_errors = 0
                        except queue.Empty:
                            continue
                        except BrokenPipeError:
                            logger.warning("[FIFO-THREAD] AI reader disconnected, will retry...")
                            break
                        except Exception as e:
                            consecutive_errors += 1
                            if consecutive_errors > 10:
                                logger.warning("[FIFO-THREAD] Too many errors, reconnecting...")
                                break
                            time.sleep(0.1)
            except Exception as e:
                logger.debug(f"[FIFO-THREAD] Connection error: {e}")
            
            logger.info("[FIFO-THREAD] Reconnecting in 3s...")
            time.sleep(3)
            # Loop continues - retry for new reader
    
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
    
    def _capture_without_fifo(self):
        """Capture flows without writing to FIFO (for dashboard only mode)"""
        logger.info("[CAPTURE] Starting capture without FIFO (dashboard metrics only)")
        # Just iterate through flows without writing to FIFO
        for _ in self._stream_flows_generator(None):
            pass
    
    def _stream_flows_generator_with_fifo(self, fifo_queue):
        """Generator to stream flows - feeds both dashboard tracker and FIFO queue"""
        logger.info(f"[STREAM-DUAL] Starting on interface: {self.iface}")
        
        # Get current timeout profile
        mode, _, profile = choose_fifo_mode()
        if profile is None:
            profile = BatPackConfig.TIMEOUT_PROFILES["NORMAL"]
            mode = "NORMAL"
        
        active_timeout = profile["ACTIVE_TIMEOUT"]
        idle_timeout = profile["IDLE_TIMEOUT"]
        
        logger.info(f"[STREAM-DUAL] Phase={mode}: {profile['desc']}")
        
        try:
            streamer = NFStreamer(
                source=self.iface,
                active_timeout=active_timeout,
                idle_timeout=idle_timeout,
                statistical_analysis=True
            )
            
            batch_json = []
            last_flush = time.time()
            flow_count = 0
            
            for flow in streamer:
                flow_count += 1
                
                # Skip loopback and IPv6
                if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                    continue
                
                # Skip restricted ports
                if flow.src_port in BatPackConfig.RESTRICTED_PORTS or \
                   flow.dst_port in BatPackConfig.RESTRICTED_PORTS:
                    continue
                
                # Extract features
                try:
                    features = extract_features(flow)
                except Exception as e:
                    logger.debug(f"[FEATURE] Extraction failed: {e}")
                    continue
                
                # [DASHBOARD] Track flow stats
                src_port = int(pick_attribute(flow, 'src_port', 'sport', default=0))
                dst_port = int(pick_attribute(flow, 'dst_port', 'dport', default=0))
                protocol = int(pick_attribute(flow, 'protocol', default=0))
                src_packets = int(pick_attribute(flow, 'src2dst_packets', 'src_packets', default=0))
                dst_packets = int(pick_attribute(flow, 'dst2src_packets', 'dst_packets', default=0))
                src_bytes = int(pick_attribute(flow, 'src2dst_bytes', 'src_bytes', default=0))
                dst_bytes = int(pick_attribute(flow, 'dst2src_bytes', 'dst_bytes', default=0))
                total_packets = src_packets + dst_packets
                total_bytes = src_bytes + dst_bytes
                
                # Track for dashboard (always)
                flow_tracker.record_flow(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    packets=total_packets,
                    bytes_cnt=total_bytes,
                    protocol=protocol
                )
                
                # Create JSON for AI (FIFO)
                json_record = {
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "dst_port": dst_port,
                    "flow_key": flow_export_key(flow),
                    "features": features
                }
                json_line = json.dumps(json_record) + "\n"
                batch_json.append(json_line)
                
                # Flush batch
                now = time.time()
                should_flush = (
                    len(batch_json) >= BatPackConfig.FLUSH_BATCH_SIZE or
                    (now - last_flush) >= BatPackConfig.FLUSH_INTERVAL
                )
                
                if should_flush and batch_json:
                    # Send to FIFO queue (non-blocking, will be discarded if queue full)
                    for line in batch_json:
                        try:
                            fifo_queue.put_nowait(line)
                        except queue.Full:
                            break  # Queue full, skip remaining
                    
                    batch_json.clear()
                    last_flush = now
                    yield json_line
                
        except Exception as e:
            logger.error(f"[STREAM-DUAL] Fatal error: {e}", exc_info=True)
    
    def _stream_flows(self, fifo_handle):
        """Stream flows to FIFO (blocking write)"""
        for _ in self._stream_flows_generator(fifo_handle):
            pass
    
    def _stream_flows_generator(self, fifo_handle):
        """Generator to stream flows from NFStreamer"""
        logger.info(f"[STREAM] Starting on interface: {self.iface}")
        
        # Get current timeout profile based on markers (attack phase detection)
        mode, _, profile = choose_fifo_mode()
        
        # [FIX] If no markers, use default NORMAL profile for IDS mode
        if profile is None:
            profile = BatPackConfig.TIMEOUT_PROFILES["NORMAL"]
            mode = "NORMAL"
        
        active_timeout = profile["ACTIVE_TIMEOUT"]
        idle_timeout = profile["IDLE_TIMEOUT"]
        is_slowloris_mode = (mode == "SLOWLORIS")
        
        logger.info(f"[PROFILE] Phase={mode}: {profile['desc']}")
        logger.info(f"[PROFILE] Using timeouts: ACTIVE={active_timeout}s, IDLE={idle_timeout}s")

        try:
            streamer = NFStreamer(
                source=self.iface,
                active_timeout=active_timeout,
                idle_timeout=idle_timeout,
                statistical_analysis=True
            )
            
            batch_json = []
            last_flush = time.time()
            
            # Track marker changes to detect phase transitions
            prev_marker_slowloris = os.path.exists(os.path.join(BASE_DIR, ".marker_slowloris"))
            prev_marker_normal = os.path.exists(os.path.join(BASE_DIR, ".marker_normal"))
            
            flow_count = 0
            logger.info(f"[NFSTREAM] Starting iteration on {self.iface}, ACTIVE={active_timeout}s, IDLE={idle_timeout}s")
            import signal
            
            def timeout_handler(signum, frame):
                logger.error("[NFSTREAM] Timeout: No flows received in 30s")
            
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(30)  # 30 second timeout
            
            try:
                for flow in streamer:
                    signal.alarm(0)  # Cancel alarm on first flow
                    flow_count += 1
                    # Debug: Log first few flows from NFStreamer
                    if flow_count <= 5:
                        logger.info(f"[NFSTREAM] Flow #{flow_count}: {flow.src_ip} -> {flow.dst_ip} "
                                  f"(sport={getattr(flow, 'src_port', 'N/A')}, dport={getattr(flow, 'dst_port', 'N/A')})")
                    
                    # Detect phase transitions via marker changes
                    curr_marker_slowloris = os.path.exists(os.path.join(BASE_DIR, ".marker_slowloris"))
                    curr_marker_normal = os.path.exists(os.path.join(BASE_DIR, ".marker_normal"))
                    
                    if curr_marker_slowloris != prev_marker_slowloris or curr_marker_normal != prev_marker_normal:
                        logger.info("[PHASE] Marker change detected, stopping to switch phase...")
                        break
                    
                    prev_marker_slowloris = curr_marker_slowloris
                    prev_marker_normal = curr_marker_normal

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
                
                    # [DASHBOARD] Track flow stats for unified metrics (web1-focused)
                    # Only track flows that pass all filters (same as AI input)
                    src_port = int(pick_attribute(flow, 'src_port', 'sport', default=0))
                    dst_port = int(pick_attribute(flow, 'dst_port', 'dport', default=0))
                    protocol = int(pick_attribute(flow, 'protocol', default=0))
                    src_packets = int(pick_attribute(flow, 'src2dst_packets', 'src_packets', default=0))
                    dst_packets = int(pick_attribute(flow, 'dst2src_packets', 'dst_packets', default=0))
                    src_bytes = int(pick_attribute(flow, 'src2dst_bytes', 'src_bytes', default=0))
                    dst_bytes = int(pick_attribute(flow, 'dst2src_bytes', 'dst_bytes', default=0))
                    total_packets = src_packets + dst_packets
                    total_bytes = src_bytes + dst_bytes
                    
                    # Debug: Log first few flows to see what's being captured
                    if self.stats['flows_processed'] < 5:
                        logger.info(f"[FLOW-CAPTURE] {flow.src_ip}:{src_port} -> {flow.dst_ip}:{dst_port} "
                                  f"(pkts={total_packets}, bytes={total_bytes}, proto={protocol})")
                    
                    flow_tracker.record_flow(
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        packets=total_packets,
                        bytes_cnt=total_bytes,
                        protocol=protocol
                    )
                    
                    # Create JSON record
                    # [NÂNG CẤP] Thêm dst_ip và dst_port để auto_dataset_generator lọc subnet chính xác
                    json_record = {
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "flow_key": flow_export_key(flow),
                        "dst_port": dst_port,
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
                        # Only write to FIFO if handle is provided (not None)
                        if fifo_handle:
                            try:
                                fifo_handle.writelines(batch_json)
                                fifo_handle.flush()
                                self.stats['flows_output'] += len(batch_json)
                                
                                if self.stats['flows_output'] % 500 == 0:
                                    logger.info(f"[STATS] Processed: {self.stats['flows_processed']}, Output: {self.stats['flows_output']}")
                            except (BrokenPipeError, FileNotFoundError):
                                # KHẮC PHỤC LỖI DEADLOCK: Ngay khi đứt Pipe, check xem có phải do chuyển Phase không!
                                if not is_slowloris_mode and os.path.exists(os.path.join(BASE_DIR, ".marker_slowloris")):
                                    logger.info("[PHASE] Đứt Pipe do chuyển sang Slowloris. Đang ngắt luồng...")
                                    break
                                elif is_slowloris_mode and os.path.exists(os.path.join(BASE_DIR, ".marker_normal")):
                                    logger.info("[PHASE] Đứt Pipe do chuyển sang Normal. Đang ngắt luồng...")
                                    break
                                    
                                logger.warning("[FIFO] Pipe closed, waiting for reconnection...")
                                time.sleep(1)
                        
                        # Clear batch regardless of whether FIFO write succeeded
                        batch_json.clear()
                        last_flush = now
                        
                        yield json_line
                
            except Exception as e:
                logger.error(f"[NFSTREAM] Error in flow processing: {e}", exc_info=True)
            
            finally:
                signal.alarm(0)  # Cancel any pending alarm
                if flow_count == 0:
                    logger.warning(f"[NFSTREAM] No flows captured in 30s timeout! Interface: {self.iface}")
                else:
                    logger.info(f"[NFSTREAM] Loop ended. Total flows seen: {flow_count}")
        
        except Exception as e:
            logger.error(f"[STREAM] Fatal error in NFStreamer loop: {e}", exc_info=True)
            logger.info(f"[STREAM] Total flows captured before error: {flow_count}")

# =====================================================================
# MAIN ENTRY POINT
# =====================================================================

def main():
    """Main function with phase detection"""
    logger.info("=" * 70)
    logger.info("🚀 BatPack v2.0 - AI v2 Data Collection Engine")
    logger.info("=" * 70)
    
    # Check for IDS/Demo mode (no markers needed)
    import sys
    IDS_MODE = "--ids" in sys.argv or "--demo" in sys.argv
    
    # Validate config
    BatPackConfig.validate()
    
    # Start NFStreamer flow tracker for dashboard (runs in background thread)
    # [FIX] Track real-time flow stats from NFStreamer (same as AI), not ONOS API
    logger.info("[MAIN] Starting NFStreamer flow tracker for dashboard...")
    flow_tracker.start()
    
    # Give tracker time to initialize
    time.sleep(0.5)
    
    # Create engine
    engine = BatPackEngine()
    
    if IDS_MODE:
        # [IDS MODE] Chạy liên tục không cần marker, dùng cho run_onos_v2
        logger.info("="*70)
        logger.info("🚀 IDS/DEMO MODE - No markers required")
        logger.info("   Chế độ này chạy liên tục cho real-time detection với run_onos_v2")
        logger.info("="*70)
        
        # Force create normal FIFO
        fifo_path = BatPackConfig.OUTPUT_FIFO_NORMAL
        create_fifo_if_needed(fifo_path)
        
        # Use default NORMAL profile
        profile = BatPackConfig.TIMEOUT_PROFILES["NORMAL"]
        logger.info(f"[IDS MODE] Using NORMAL profile: ACTIVE={profile['ACTIVE_TIMEOUT']}s, IDLE={profile['IDLE_TIMEOUT']}s")
        logger.info(f"[IDS MODE] Output to: {fifo_path}")
        
        # Chạy liên tục không thoát
        engine.capture_normal_and_attack()
    else:
        # [AUTO MODE] Check for markers, fallback to IDS mode if none
        mode, fifo_path, profile = choose_fifo_mode()
        
        if mode is None:
            # [FIX] No markers = auto switch to IDS mode for run_onos_v2 compatibility
            logger.info("[AUTO MODE] No markers detected. Switching to IDS mode for run_onos_v2...")
            logger.info("="*70)
            logger.info("🚀 IDS/DEMO MODE - Auto-selected (no markers)")
            logger.info("   Chế độ này chạy liên tục cho real-time detection với run_onos_v2")
            logger.info("="*70)
            
            # Force create normal FIFO
            fifo_path = BatPackConfig.OUTPUT_FIFO_NORMAL
            create_fifo_if_needed(fifo_path)
            
            # Use default NORMAL profile
            profile = BatPackConfig.TIMEOUT_PROFILES["NORMAL"]
            logger.info(f"[AUTO MODE] Using NORMAL profile: ACTIVE={profile['ACTIVE_TIMEOUT']}s, IDLE={profile['IDLE_TIMEOUT']}s")
            logger.info(f"[AUTO MODE] Output to: {fifo_path}")
            
            # Chạy liên tục không thoát
            engine.capture_normal_and_attack()
        else:
            # [DATASET MODE] Có marker từ auto_dataset_generator
            logger.info(f"[DATASET MODE] Detected marker: {mode}")
            
            if mode == "SLOWLORIS":
                engine.capture_slowloris()
            elif mode == "NORMAL":
                engine.capture_normal_and_attack()
            else:
                logger.info("[DATASET MODE] Running with detected mode...")
                engine.capture_normal_and_attack()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n[EXIT] Interrupted by user")
    except Exception as e:
        logger.critical(f"[FATAL] Unhandled error: {e}", exc_info=True)
