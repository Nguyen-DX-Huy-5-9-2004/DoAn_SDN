# Tên file: ids_onos_integration.py
# Hệ thống IDS nâng cấp với ONOS/OVS Integration cho việc thực thi DROP thực tế

import requests
import time
import json
import logging
from typing import Dict, List, Tuple
from requests.auth import HTTPBasicAuth
import subprocess

# =====================================================================
# PHẦN 1: LOGGING & CẤU HÌNH
# =====================================================================

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/tmp/ids_onos.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

ONOS_CONTROLLER_IP = "172.17.0.2"
ONOS_CONTROLLER_REST_PORT = 8181
ONOS_REST_USER = "onos"
ONOS_REST_PASSWORD = "rocks"

# Switch configuration
INGRESS_SWITCH_ID = "of:0000000000000006"    # s6 - Gateway (Chặng 1)
SECONDARY_SWITCH_ID = "of:0000000000000005"  # s5 - Backend (Chặng 2)

# IDS Configuration
IP_PREDICTION_HISTORY = {}  # {ip: [(label, timestamp), ...]}
HISTORY_WINDOW = 5          # Giữ lịch sử 5 chuỗi gần nhất
DROP_THRESHOLD = 3          # Nếu 3/5 chuỗi là Attack -> DROP
BLOCK_DURATION_SEC = 600    # Giữ lệnh DROP 10 phút

# Tracking
BLOCKED_IPS = {}            # {ip: (timestamp, attack_type, flow_rule_id), ...}

# =====================================================================
# PHẦN 2: ONOS REST API CLIENT
# =====================================================================

class ONOSClient:
    """Client để giao tiếp với ONOS Controller qua REST API"""
    
    def __init__(self, controller_ip=ONOS_CONTROLLER_IP, 
                 rest_port=ONOS_CONTROLLER_REST_PORT,
                 username=ONOS_REST_USER,
                 password=ONOS_REST_PASSWORD):
        self.base_url = f"http://{controller_ip}:{rest_port}"
        self.auth = HTTPBasicAuth(username, password)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({'Content-Type': 'application/json'})
    
    def check_connectivity(self):
        """Kiểm tra kết nối tới ONOS"""
        try:
            resp = self.session.get(f"{self.base_url}/onos/v1/devices", timeout=5)
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"[ONOS] Không thể kết nối: {e}")
            return False
    
    def get_device_id_by_name(self, switch_name):
        """Lấy device ID từ tên switch (ví dụ: s6 -> of:0000000000000006)"""
        try:
            resp = self.session.get(f"{self.base_url}/onos/v1/devices", timeout=5)
            if resp.status_code == 200:
                devices = resp.json().get('devices', [])
                for device in devices:
                    if switch_name.lower() in device.get('id', '').lower():
                        return device['id']
        except Exception as e:
            logger.error(f"[ONOS] Error getting device: {e}")
        return None
    
    def add_flow_rule(self, device_id, src_ip, priority=1000, timeout=600):
        """
        Thêm Flow Rule để DROP traffic từ src_ip
        
        device_id: of:0000000000000006 (s6)
        src_ip: 10.0.1.x (IP bị block)
        priority: 1000 (cao nhất, ghi đè các luật khác)
        timeout: 600 giây
        """
        try:
            flow_rule = {
                "deviceId": device_id,
                "flowId": hash(f"{device_id}_{src_ip}_{time.time()}") & 0x7fffffff,
                "isPermanent": False,
                "timeout": timeout,
                "priority": priority,
                "tableId": 0,
                "treatment": {
                    "instructions": [
                        {
                            "type": "OUTPUT",
                            "port": "CONTROLLER"  # Hoặc "DROP" nếu hỗ trợ
                        }
                    ]
                },
                "selector": {
                    "criteria": [
                        {
                            "type": "ETH_TYPE",
                            "ethType": "0x0800"  # IPv4
                        },
                        {
                            "type": "IPV4_SRC",
                            "ip": f"{src_ip}/32"
                        }
                    ]
                }
            }
            
            url = f"{self.base_url}/onos/v1/flows/{device_id}"
            resp = self.session.post(url, json=flow_rule, timeout=10)
            
            if resp.status_code in [200, 201]:
                logger.info(f"[ONOS] Flow rule added: DROP {src_ip} at {device_id}")
                return True
            else:
                logger.error(f"[ONOS] Failed to add flow rule: {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"[ONOS] Error adding flow rule: {e}")
            return False
    
    def remove_flow_rule(self, device_id, src_ip):
        """Xóa Flow Rule (unblock IP)"""
        try:
            flow_id = hash(f"{device_id}_{src_ip}") & 0x7fffffff
            url = f"{self.base_url}/onos/v1/flows/{device_id}/{flow_id}"
            resp = self.session.delete(url, timeout=10)
            
            if resp.status_code == 204:
                logger.info(f"[ONOS] Flow rule removed: UNBLOCK {src_ip}")
                return True
            else:
                logger.error(f"[ONOS] Failed to remove flow rule: {resp.status_code}")
                return False
        except Exception as e:
            logger.error(f"[ONOS] Error removing flow rule: {e}")
            return False


# =====================================================================
# PHẦN 3: OVS-OFCTL FALLBACK (Khi ONOS không available)
# =====================================================================

class OVSClient:
    """Fallback: Sử dụng ovs-ofctl command line để thao tác Flow Rules"""
    
    @staticmethod
    def add_drop_rule(switch_name, src_ip, priority=1000, timeout=600):
        """
        Thêm luật DROP vào OVS switch (nếu ONOS không hoạt động)
        
        Ví dụ lệnh: ovs-ofctl add-flow s6 "priority=1000,ip,nw_src=10.0.1.100,actions=drop"
        """
        try:
            rule = f"priority={priority},ip,nw_src={src_ip},actions=drop"
            cmd = ["ovs-ofctl", "add-flow", switch_name, rule]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.info(f"[OVS] DROP rule added: {src_ip} on {switch_name}")
                return True
            else:
                logger.error(f"[OVS] Failed to add DROP rule: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"[OVS] Error adding DROP rule: {e}")
            return False
    
    @staticmethod
    def remove_drop_rule(switch_name, src_ip):
        """
        Xóa luật DROP từ OVS switch
        
        Ví dụ lệnh: ovs-ofctl del-flows s6 "ip,nw_src=10.0.1.100"
        """
        try:
            rule = f"ip,nw_src={src_ip}"
            cmd = ["ovs-ofctl", "del-flows", switch_name, rule]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.info(f"[OVS] DROP rule removed: {src_ip} on {switch_name}")
                return True
            else:
                logger.error(f"[OVS] Failed to remove DROP rule: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"[OVS] Error removing DROP rule: {e}")
            return False


# =====================================================================
# PHẦN 4: IDS ENGINE - HỆ THỐNG PHÁT HIỆN & NGĂN CHẶN
# =====================================================================

class IDSEngine:
    """
    Hệ thống IDS với Temporal Consistency Monitoring
    - Theo dõi lịch sử dự đoán từng IP
    - Thực thi DROP action khi phát hiện tấn công nhất quán
    - Tự động unblock sau timeout
    """
    
    LABEL_MAP = {
        0: "BENIGN",
        1: "UDP_FLOOD",
        2: "SYN_FLOOD",
        3: "HTTP_FLOOD",
        4: "SLOWLORIS"
    }
    
    def __init__(self, use_onos=True):
        self.use_onos = use_onos
        
        if use_onos:
            self.onos = ONOSClient()
            if not self.onos.check_connectivity():
                logger.warning("[IDS] ONOS không phản hồi, chuyển sang OVS fallback")
                self.use_onos = False
        
        # Thread để auto-unblock IPs
        self._start_cleanup_thread()
    
    def process_prediction(self, src_ip, predicted_label, confidence=1.0):
        """
        Xử lý dự đoán từ AI model
        
        Args:
            src_ip: IP nguồn (10.0.1.x)
            predicted_label: 0-4 (Benign/UDP/SYN/HTTP/Slowloris)
            confidence: 0.0-1.0 (độ tin cậy của dự đoán)
        
        Returns:
            (action: "PASS"/"MONITOR"/"BLOCK", reason: str)
        """
        
        # Bình thường -> Không làm gì
        if predicted_label == 0:
            if src_ip in IP_PREDICTION_HISTORY:
                del IP_PREDICTION_HISTORY[src_ip]
            return "PASS", "Normal traffic"
        
        # Attack detected -> Lưu lịch sử
        if src_ip not in IP_PREDICTION_HISTORY:
            IP_PREDICTION_HISTORY[src_ip] = []
        
        IP_PREDICTION_HISTORY[src_ip].append((predicted_label, time.time()))
        
        # Giữ lịch sử trong HISTORY_WINDOW
        if len(IP_PREDICTION_HISTORY[src_ip]) > HISTORY_WINDOW:
            IP_PREDICTION_HISTORY[src_ip].pop(0)
        
        # Kiểm tra tính nhất quán
        recent_attacks = sum(1 for label, _ in IP_PREDICTION_HISTORY[src_ip] if label != 0)
        
        action_reason = {
            "src_ip": src_ip,
            "predicted_label": self.LABEL_MAP.get(predicted_label, "UNKNOWN"),
            "consistency": f"{recent_attacks}/{HISTORY_WINDOW}",
            "confidence": f"{confidence:.2%}"
        }
        
        # Nếu đủ nhất quán -> BLOCK
        if recent_attacks >= DROP_THRESHOLD:
            success = self._execute_drop(src_ip, predicted_label)
            if success:
                BLOCKED_IPS[src_ip] = (time.time(), predicted_label, None)
                action_reason["status"] = "BLOCKED"
                logger.warning(f"🛡️ BLOCKED: {action_reason}")
                return "BLOCK", json.dumps(action_reason)
            else:
                logger.error(f"[IDS] Failed to execute DROP for {src_ip}")
                return "MONITOR", f"Drop execution failed: {action_reason}"
        
        # Chưa đủ nhất quán -> MONITOR
        action_reason["status"] = "MONITORING"
        logger.info(f"📊 MONITOR: {action_reason}")
        return "MONITOR", json.dumps(action_reason)
    
    def _execute_drop(self, src_ip, attack_type):
        """
        Thực thi DROP action qua ONOS hoặc OVS
        """
        if self.use_onos:
            # Cố gắng dùng ONOS trước
            device_id = self.onos.get_device_id_by_name("s6")
            if device_id:
                return self.onos.add_flow_rule(device_id, src_ip, priority=1000, timeout=BLOCK_DURATION_SEC)
        
        # Fallback: Dùng OVS trực tiếp
        return OVSClient.add_drop_rule("s6", src_ip, priority=1000, timeout=BLOCK_DURATION_SEC)
    
    def _execute_unblock(self, src_ip):
        """Xóa lệnh DROP (unblock IP)"""
        if self.use_onos:
            device_id = self.onos.get_device_id_by_name("s6")
            if device_id:
                self.onos.remove_flow_rule(device_id, src_ip)
                return
        
        # Fallback: OVS
        OVSClient.remove_drop_rule("s6", src_ip)
    
    def _start_cleanup_thread(self):
        """Thread để tự động unblock IPs sau timeout"""
        import threading
        
        def cleanup_loop():
            while True:
                try:
                    time.sleep(60)  # Kiểm tra mỗi 1 phút
                    
                    current_time = time.time()
                    expired_ips = []
                    
                    for src_ip, (block_time, attack_type, _) in BLOCKED_IPS.items():
                        if current_time - block_time > BLOCK_DURATION_SEC:
                            expired_ips.append(src_ip)
                    
                    for src_ip in expired_ips:
                        logger.info(f"[IDS] Auto-unblocking {src_ip} (timeout)")
                        self._execute_unblock(src_ip)
                        del BLOCKED_IPS[src_ip]
                        if src_ip in IP_PREDICTION_HISTORY:
                            del IP_PREDICTION_HISTORY[src_ip]
                
                except Exception as e:
                    logger.error(f"[IDS] Cleanup thread error: {e}")
        
        thread = threading.Thread(target=cleanup_loop, daemon=True)
        thread.start()
    
    def get_status(self):
        """Lấy trạng thái hiện tại của IDS"""
        return {
            "blocked_ips": list(BLOCKED_IPS.keys()),
            "monitoring_ips": list(IP_PREDICTION_HISTORY.keys()),
            "total_blocked": len(BLOCKED_IPS),
            "total_monitoring": len(IP_PREDICTION_HISTORY),
            "timestamp": time.time()
        }


# =====================================================================
# PHẦN 5: FACTORY & HELPER
# =====================================================================

# Global IDS Engine instance
_ids_engine = None

def initialize_ids(use_onos=True):
    """Khởi tạo IDS Engine"""
    global _ids_engine
    _ids_engine = IDSEngine(use_onos=use_onos)
    logger.info("[IDS] Engine initialized")
    return _ids_engine

def process_ai_prediction(src_ip, predicted_label, confidence=1.0):
    """
    Interface chính để xử lý dự đoán từ AI model
    
    Được gọi từ ai_monitor.py khi có dự đoán mới
    """
    if _ids_engine is None:
        initialize_ids(use_onos=True)
    
    return _ids_engine.process_prediction(src_ip, predicted_label, confidence)

def get_ids_status():
    """Lấy trạng thái IDS"""
    if _ids_engine is None:
        return {"error": "IDS not initialized"}
    
    return _ids_engine.get_status()


# =====================================================================
# PHẦN 6: LEGACY COMPATIBILITY (Để tương thích với system.py cũ)
# =====================================================================

def apply_ips_decision_v2(src_ip, label, confidence):
    """
    Hàm tương thích với version cũ của system.py
    Nhưng sử dụng IDS engine nâng cấp
    """
    action, reason = process_ai_prediction(src_ip, label, confidence)
    return action, reason


if __name__ == "__main__":
    # Test
    print("[*] Initializing IDS Engine...")
    ids = initialize_ids(use_onos=True)
    
    print("\n[TEST] Simulating attack sequence:")
    test_ip = "10.0.1.100"
    
    for i in range(5):
        action, reason = process_ai_prediction(test_ip, label=1, confidence=0.95)
        print(f"  Prediction {i+1}: {action} - {reason}")
        time.sleep(0.5)
    
    print(f"\n[STATUS] {get_ids_status()}")
