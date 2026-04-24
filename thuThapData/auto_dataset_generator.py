import json, os, time, csv, sys, socket, subprocess, ssl
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# --- CẤU HÌNH TỐI ƯU ---
# Cấu hình số lượng mẫu
TARGET_SAMPLES_PER_CLASS = 100000  # 100k cho mỗi loại tấn công
NORMAL_SAMPLES_TARGET = 200000     # 200k cho lưu lượng bình thường
FIFO_PATH = os.path.join(BASE_DIR, "..", "ai", "zeek_stream.json")
OUTPUT_CSV = "master_dataset_v7.csv"
WEB_RESTART_CMD = os.environ.get("WEB_RESTART_CMD", "").strip()
SLOWLORIS_HEALTH_URL = os.environ.get("SLOWLORIS_TARGET_URL", "http://127.0.0.1:8000")

# Buffer ghi CSV lớn để giảm I/O
CSV_WRITE_BATCH = 1000
PROGRESS_EVERY = 500

# CÂN ĐỒI: Filter thông minh loại bỏ system traffic nhưng giữ lại attack/normal flows
# Bật = 1: Filter trên SOURCE subnet (attack/client) và DESTINATION (web targets)
#         + Loại bỏ system flows từ IDS/monitoring (h80-h82)
#         + Loại bỏ DNS flows (port 53)
# Tắt = 0: Accept tất cả flows (quá nhiều noise)
SMART_SUBNET_FILTER = os.environ.get("SMART_SUBNET_FILTER", "1") == "1"

# Danh sách target servers chúng ta quan tâm (web traffic)
TARGET_SERVICES = ["10.0.0.10", "10.0.0.11"]  # proxy1, web1
TARGET_PORTS = [80, 443, 8000]  # HTTP, HTTPS, Django

# Danh sách system hosts cần loại bỏ (IDS, monitoring, etc)
SYSTEM_HOSTS_TO_EXCLUDE = [
    "10.0.0.100", "10.0.0.101", "10.0.0.102",  # h70, h71, h72 (services)
    "10.0.0.200", "10.0.0.201", "10.0.0.202",  # h80, h81, h82 (IDS, honeypot, monitor)
    "10.0.0.20"   # db1 (database - not web traffic)
]

# 5-CLASS LABELS
LABELS = {
    0: "Normal",
    1: "UDP Flood",
    2: "SYN Flood",
    3: "HTTP Flood",
    4: "Slowloris"
}

# ====================================================================
# MARKER MANAGEMENT FOR PHASE-SPECIFIC TUNING
# ====================================================================
def create_phase_marker(label_id):
    """Create phase-specific marker to signal batPack_v2 for timeout tuning"""
    markers_base = os.path.join(BASE_DIR, "..", "ai")
    
    marker_map = {
        0: os.path.join(markers_base, ".marker_normal"),
        1: os.path.join(markers_base, ".marker_udp"),
        2: os.path.join(markers_base, ".marker_syn"),
        3: os.path.join(markers_base, ".marker_http"),
        4: os.path.join(markers_base, ".marker_slowloris"),
    }
    
    # Remove all old markers
    for m in marker_map.values():
        try:
            if os.path.exists(m):
                os.remove(m)
        except Exception:
            pass
    
    # Create new marker for this phase
    marker_path = marker_map.get(label_id)
    if marker_path:
        try:
            with open(marker_path, 'w') as f:
                f.write("1")
            label_name = LABELS.get(label_id, "Unknown")
            print(f"[MARKER] Created .marker_{label_name.lower().split()[0]} for phase {label_id}")
        except Exception as e:
            print(f"[ERROR] Failed to create marker: {e}")

def cleanup_all_markers():
    """Remove all phase markers"""
    markers_base = os.path.join(BASE_DIR, "..", "ai")
    markers = [
        os.path.join(markers_base, ".marker_normal"),
        os.path.join(markers_base, ".marker_udp"),
        os.path.join(markers_base, ".marker_syn"),
        os.path.join(markers_base, ".marker_http"),
        os.path.join(markers_base, ".marker_slowloris"),
    ]
    
    for m in markers:
        try:
            if os.path.exists(m):
                os.remove(m)
        except Exception:
            pass

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def prompt_user(step_name, cmd_to_copy):
    """Hàm dừng chương trình, yêu cầu người dùng copy lệnh vào Mininet"""
    print("\n" + "="*70)
    print(f"👉 BƯỚC: {step_name}")
    print("="*70)
    print("[1] Hãy COPY lệnh dưới đây và DÁN vào Terminal Mininet (containernet>):")
    print(f"\033[92m{cmd_to_copy}\033[0m") # In màu xanh lá cho dễ nhìn
    print("-" * 70)
    print("[💡 LƯU Ý]")
    print("   • Đảm bảo Web1 đang chạy: containernet> web1 ps aux | grep manage.py")
    print("   • Nếu không có Django, chạy: containernet> web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000 &'")
    print("-" * 70)
    input("[2] Sau khi gõ xong bên Mininet, HÃY BẤM ENTER TẠI ĐÂY ĐỂ TIẾP TỤC...")
    print("[*] Đang tiến hành thu thập dữ liệu ở tốc độ cao...\n")

def _parse_target_url(raw_target):
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


def _is_target_alive(host, port, timeout=5):
    try:
        url = f"http://{host}:{port}/"
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return True
        else:
            print(f"[DEBUG] Health check failed: {url} returned {response.status_code}")
            return False
    except Exception as e:
        print(f"[DEBUG] Health check exception: {e}")
        return False


def _restart_webserver_if_configured():
    if not WEB_RESTART_CMD:
        print("[GENERATOR] WEB_RESTART_CMD chưa cấu hình, không thể restart tự động.")
        return False
    try:
        subprocess.run(WEB_RESTART_CMD, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[GENERATOR] Đã gửi lệnh restart webserver tự động.")
        time.sleep(5)
        return True
    except Exception as e:
        print(f"[GENERATOR] Lỗi khi restart webserver: {e}")
        return False


def _wait_for_target_alive(target_url, max_retry=3, interval=2):
    host, port = _parse_target_url(target_url)
    for attempt in range(1, max_retry + 1):
        if _is_target_alive(host, port):
            return True
        print(f"[GENERATOR] Web server {host}:{port} chưa trả lời (attempt {attempt}/{max_retry}).")
        time.sleep(interval)
    # Nếu fail sau max_retry, prompt user để khởi động web
    print("\n" + "="*70)
    print("🚨 WEB SERVER KHÔNG PHẢN HỒI SAU 3 LẦN THỬ!")
    print("="*70)
    print(f"Web target {host}:{port} vẫn chưa trả lời.")
    print("Hãy khởi động web server bằng lệnh trong Mininet:")
    print("containernet> web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000 &'")
    print("-" * 70)
    input("Sau khi khởi động xong, HÃY BẤM ENTER TẠI ĐÂY ĐỂ CHECK LẠI...")
    # Check lại sau khi user nhấn enter
    return _wait_for_target_alive(target_url, max_retry=3, interval=2)


def collect_data(label_id, target_samples=TARGET_SAMPLES_PER_CLASS, description="", fifo_path=None, health_check_url=None):
    # Xác định đúng FIFO path dựa trên label (Luôn tìm trong thư mục ../ai/)
    if fifo_path is None:
        base_ai_dir = os.path.join(BASE_DIR, "..", "ai")
        fifo_path = os.path.join(base_ai_dir, "zeek_stream_slowloris.json") if label_id == 4 else os.path.join(base_ai_dir, "zeek_stream.json")

    # Signal ai/batPack_v2.py which mode to use
    marker_slowloris = os.path.join(BASE_DIR, "..", "ai", ".marker_slowloris")
    marker_normal = os.path.join(BASE_DIR, "..", "ai", ".marker_normal")

    # [FIX] Chỉ tạo marker nếu chưa đúng loại - tránh batPack restart liên tục
    os.makedirs(os.path.dirname(marker_slowloris), exist_ok=True)
    
    if label_id == 4:
        # Slowloris phase: cần marker_slowloris
        if not os.path.exists(marker_slowloris):
            # Xóa marker cũ nếu có
            if os.path.exists(marker_normal):
                os.remove(marker_normal)
            open(marker_slowloris, "w").close()
            print(f"[GENERATOR] Tạo marker SLOWLORIS: {marker_slowloris}")
            time.sleep(0.5)  # Chỉ sleep khi thực sự tạo marker mới
        else:
            print(f"[GENERATOR] Giữ nguyên marker SLOWLORIS (đã tồn tại)")
        marker_created = marker_slowloris
    else:
        # Normal/Attack phases (0-3): cần marker_normal
        if not os.path.exists(marker_normal):
            # Xóa marker cũ nếu có
            if os.path.exists(marker_slowloris):
                os.remove(marker_slowloris)
            open(marker_normal, "w").close()
            print(f"[GENERATOR] Tạo marker NORMAL: {marker_normal}")
            time.sleep(0.5)  # Chỉ sleep khi thực sự tạo marker mới
        else:
            print(f"[GENERATOR] Giữ nguyên marker NORMAL (đã tồn tại)")
        marker_created = marker_normal

    display_label = LABELS[label_id] if not description else f"{LABELS[label_id]} ({description})"
    print(f"\n[GENERATOR] Đang thu thập dữ liệu cho: {display_label}")
    print(f"[GENERATOR] Sử dụng FIFO: {fifo_path}")

    collected = 0
    batch_data = []
    dropped_by_subnet = 0
    dropped_invalid = 0
    raw_lines = 0

    # DEBUG TRACKING
    debug_stats = {
        "total": 0,
        "from_client": 0,
        "to_web": 0,
        "port_8000": 0,
        "pass_system_filter": 0,
        "pass_dns_filter": 0,
        "pass_subnet_filter": 0,
        "pass_web_filter": 0,
        "features_len_13": 0
    }
    DEBUG_MODE = False  # Đã fix xong, tắt debug để chạy nhanh

    # Đợi cho đến khi batPack tạo ra FIFO
    while not os.path.exists(fifo_path):
        print(f"[GENERATOR] Đang đợi ai/batPack_v2.py tạo Named Pipe: {fifo_path}...", end="\r")
        time.sleep(1)

    if label_id == 4 and health_check_url:
        if not _wait_for_target_alive(health_check_url):
            print(f"[GENERATOR] Web target {health_check_url} không phản hồi. Dừng thu nhãn Slowloris.")
            return
    try:
        with open(OUTPUT_CSV, "a", newline="") as csv_file:
            writer = csv.writer(csv_file)

            with open(fifo_path, "r") as fifo:
                ignore_until = time.time() + 2.0
                last_print_time = time.time()
                last_health_check = time.time()
                health_check_interval = 10.0

                while collected < target_samples:
                    now = time.time()
                    if label_id == 4 and health_check_url and (now - last_health_check) >= health_check_interval:
                        if not _wait_for_target_alive(health_check_url, max_retry=1, interval=1):
                            print("\n[GENERATOR] Web target slowloris đã tắt trong quá trình thu. Dừng thu để tránh dữ liệu nhiễu.")
                            break
                        last_health_check = now

                    line = fifo.readline()
                    now = time.time()

                    if now - last_print_time > 1.0:
                        print(f"   [Đang quét] Tiến độ: {collected:,}/{target_samples:,} | raw={raw_lines:,} invalid={dropped_invalid:,} drop_subnet={dropped_by_subnet:,}   ", end="\r")
                        last_print_time = now

                    if not line:
                        time.sleep(0.001)
                        continue
                    raw_lines += 1

                    if time.time() < ignore_until:
                        continue

                    try:
                        data = json.loads(line)
                        src_ip = data.get("src_ip", data.get("id.orig_h", data.get("ip", "")))
                        dst_ip = data.get("dst_ip", data.get("id.resp_h", ""))
                        dst_port = data.get("dst_port", 0)  # [FIX] Lấy từ JSON, không phải features[1]
                        features = data.get("features", [])
                        # [NÂNG CẤP] features[0] và features[1] giờ là Entropy, không phải port numbers
                        src_port_entropy = features[0] if len(features) > 0 else 0
                        dst_port_entropy = features[1] if len(features) > 1 else 0

                        if DEBUG_MODE and raw_lines < 3:
                            print(f"[DEBUG STRUCTURE] Raw JSON keys: {list(data.keys())}")
                            print(f"[DEBUG STRUCTURE] Flow #{raw_lines}: src_ip={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, features_len={len(features)}")
                            if len(features) >= 2:
                                print(f"[DEBUG STRUCTURE]   features[0]={features[0]}, features[1]={features[1]}")

                        debug_stats["total"] += 1
                        if src_ip.startswith("10.0.2."):
                            debug_stats["from_client"] += 1
                        if dst_ip in TARGET_SERVICES:
                            debug_stats["to_web"] += 1
                        if dst_port == 8000:
                            debug_stats["port_8000"] += 1

                        if SMART_SUBNET_FILTER:
                            if src_ip in SYSTEM_HOSTS_TO_EXCLUDE or dst_ip in SYSTEM_HOSTS_TO_EXCLUDE:
                                dropped_by_subnet += 1
                                if DEBUG_MODE and raw_lines < 20:
                                    print(f"[DEBUG] Flow #{raw_lines} REJECTED by SYSTEM_HOSTS filter: {src_ip} → {dst_ip}")
                                continue
                            debug_stats["pass_system_filter"] += 1

                            if dst_port == 53:
                                dropped_by_subnet += 1
                                if DEBUG_MODE and raw_lines < 20:
                                    print(f"[DEBUG] Flow #{raw_lines} REJECTED by DNS filter: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                                continue
                            debug_stats["pass_dns_filter"] += 1

                            is_attack_or_client = (
                                src_ip.startswith("10.0.1.") or src_ip.startswith("10.0.2.") or
                                dst_ip.startswith("10.0.1.") or dst_ip.startswith("10.0.2.")
                            )
                            is_web_traffic = (
                                (dst_ip in TARGET_SERVICES or dst_port in TARGET_PORTS) or
                                (src_ip in TARGET_SERVICES and src_port in TARGET_PORTS)
                            )

                            if DEBUG_MODE and raw_lines < 50:
                                status = "✅ PASS" if (is_attack_or_client and is_web_traffic) else "❌ FAIL"
                                print(f"[DEBUG] Flow #{raw_lines} {status}: {src_ip}:{src_port}→{dst_ip}:{dst_port} | is_client={is_attack_or_client} is_web={is_web_traffic}")

                            if not (is_attack_or_client and is_web_traffic):
                                dropped_by_subnet += 1
                                continue
                            debug_stats["pass_subnet_filter"] += 1
                            debug_stats["pass_web_filter"] += 1

                        if len(features) == 13:
                            debug_stats["features_len_13"] = debug_stats.get("features_len_13", 0) + 1
                            
                            # LOGIC DÁN NHÃN THÔNG MINH (CHỐNG NHIỄM ĐỘC DATA)
                            actual_label = label_id
                            
                            # CỰC KỲ QUAN TRỌNG: Chỉ chấp nhận nhãn Normal (0) từ dải Client (10.0.2.x)
                            # để AI học đúng hành vi của người dùng thật.
                            if label_id == 0:
                                if not src_ip.startswith("10.0.2."):
                                    dropped_by_subnet += 1
                                    continue # Bỏ qua traffic từ các nguồn khác (system, db, botnet cũ)
                            
                            # Nếu đang trong pha tấn công (1,2,3,4) nhưng Src_IP không thuộc Botnet (10.0.1.x)
                            # thì đó là traffic Normal phát sinh ngẫu nhiên -> Dán nhãn 0
                            elif label_id != 0:
                                is_botnet_src = src_ip.startswith("10.0.1.")
                                if not is_botnet_src:
                                    actual_label = 0 
                            
                            row = features + [actual_label]
                            batch_data.append(row)
                            collected += 1

                            if len(batch_data) >= CSV_WRITE_BATCH:
                                writer.writerows(batch_data)
                                batch_data.clear()
                        else:
                            dropped_invalid += 1

                    except Exception as e:
                        if DEBUG_MODE and raw_lines < 5:
                            print(f"[ERROR] JSON parse error on line #{raw_lines}: {str(e)[:100]}")
                        dropped_invalid += 1
                        continue

                if batch_data:
                    writer.writerows(batch_data)

    finally:
        # CỰC KỲ QUAN TRỌNG: Xóa markers để batPack_v2 quay về chế độ mặc định
        marker_slowloris = os.path.join(BASE_DIR, "..", "ai", ".marker_slowloris")
        marker_normal = os.path.join(BASE_DIR, "..", "ai", ".marker_normal")
        for m in [marker_slowloris, marker_normal]:
            try:
                if os.path.exists(m):
                    os.remove(m)
                    print(f"[CLEANUP] Đã xóa marker: {os.path.basename(m)}")
            except Exception as e:
                print(f"[CLEANUP] Lỗi khi xóa marker {m}: {e}")

    if DEBUG_MODE:
        print("\n[DEBUG STATS]:")
        print(f"  Total flows: {debug_stats['total']}")
        print(f"  From client 10.0.2.x: {debug_stats['from_client']}")
        print(f"  To web (10.0.0.10/11): {debug_stats['to_web']}")
        print(f"  On port 8000: {debug_stats['port_8000']}")
        print(f"  Pass system filter: {debug_stats['pass_system_filter']}")
        print(f"  Pass DNS filter: {debug_stats['pass_dns_filter']}")
        print(f"  Pass subnet filter: {debug_stats['pass_subnet_filter']}")
        print(f"  Pass web filter: {debug_stats['pass_web_filter']}")
        print(f"  Features len==13: {debug_stats['features_len_13']}")

    print(
        f"\n✅ Xong! Đã thu thập {collected:,} mẫu cho {display_label} | "
        f"raw={raw_lines:,} invalid={dropped_invalid:,} drop_subnet={dropped_by_subnet:,}"
    )


def main():
    if os.getuid() != 0:
        print("Lỗi: Phải chạy bằng 'sudo python3 thuThapData/auto_dataset_generator.py'")
        return

    # Clean up any leftover markers from previous runs
    cleanup_all_markers()
    print("[GENERATOR] Cleaned all leftover markers")

    headers = ["Src_Port_Entropy", "Dst_Port_Entropy", "Protocol", "Duration_Sec", 
               "Src_Bytes", "Dst_Bytes", "Src_Packets", "Dst_Packets", 
               "Conn_State", "L7_App_Protocol", "Packet_Rate", "Byte_Rate", 
               "Anomaly_Score", "target_label"]
    
    if not os.path.exists(OUTPUT_CSV):
        with open(OUTPUT_CSV, 'w', newline='') as f: 
            csv.writer(f).writerow(headers)

    clear_screen()
    print("="*70)
    print("🚀 QUY TRÌNH THU THẬP DATASET PHÂN LOẠI CHI TIẾT (5 NHÃN)")
    print("="*70)
    print("[📋] Thứ tự TỐI ƯU: NORMAL PHASE (0) → ATTACK PHASES (1-4)")
    print("[⚡] Lý do: Normal không cần attack, sau đó mới tới attack phases")
    print("="*70)

    # 📌 NORMAL PHASE FIRST (0) - Không cần attack nào chạy
    print("\n[PHASE 0️⃣ ] NORMAL TRAFFIC - 50 min (FIRST)")
    print("[💡] Chỉ bắt traffic từ clients (10.0.2.x) → web servers")
    print("[*] Không cần khởi chạy tấn công, chỉ web server bình thường")
    
    # Create marker for Normal phase
    create_phase_marker(0)
    
    prompt_user(f"KHỞI ĐỘNG: Normal Traffic từ Clients", 
                "py [net.get(f'h{i}').cmd('python3 traffic/normal.py http://10.0.0.10:8000 &') for i in range(60, 66)]")
    collect_data(0, target_samples=NORMAL_SAMPLES_TARGET)
    
    cleanup_all_markers()
    print("[*] Đang dọn dẹp bộ đệm (chờ 3s)...")
    time.sleep(3)

    # 📌 ATTACK PHASES (1-4) - Sau khi đã thu Normal
    cmd_attack_stop = "py [net.get(f'h{i}').cmd('pkill -f attack/') for i in range(1, 21)]"

    # PHASE 1: UDP Flood -> Đích: Proxy (10.0.0.10)
    print("\n[PHASE 1️⃣ ] UDP FLOOD ATTACK - 10 min")
    print("[💡] UDP: Unidirectional, chỉ gửi không chờ nhận")
    print("[*] Tuning: Shorter timeouts (ACTIVE=3s, IDLE=1s)")
    
    create_phase_marker(1)
    
    prompt_user(f"BẬT TẤN CÔNG: UDP Flood", "py [net.get(f'h{i}').cmd('python3 attack/udp_flood.py 10.0.0.10 &') for i in range(1, 4)]")
    collect_data(1, target_samples=TARGET_SAMPLES_PER_CLASS)
    prompt_user(f"DỪNG TẤN CÔNG: UDP Flood", cmd_attack_stop)
    cleanup_all_markers()
    print("[*] Đang dọn dẹp bộ đệm (chờ 3s)...")
    time.sleep(3)

    # PHASE 2: SYN Flood -> Đích: Proxy (10.0.0.10)
    print("\n[PHASE 2️⃣ ] SYN FLOOD ATTACK - 10 min")
    print("[💡] SYN: Half-open connections, bắt incomplete 3-way handshake")
    print("[*] Tuning: Medium timeouts (ACTIVE=5s, IDLE=2s)")
    
    create_phase_marker(2)
    
    prompt_user(f"BẬT TẤN CÔNG: SYN Flood", "py [net.get(f'h{i}').cmd('python3 attack/syn_flood.py 10.0.0.10 &') for i in range(5, 8)]")
    collect_data(2, target_samples=TARGET_SAMPLES_PER_CLASS)
    prompt_user(f"DỪNG TẤN CÔNG: SYN Flood", cmd_attack_stop)
    cleanup_all_markers()
    print("[*] Đang dọn dẹp bộ đệm (chờ 3s)...")
    time.sleep(3)

    # PHASE 3: HTTP Flood -> Đích: Proxy (10.0.0.10)
    print("\n[PHASE 3️⃣ ] HTTP FLOOD ATTACK - 10 min")
    print("[💡] HTTP: Layer 7, bắt request HTTP floods")
    print("[*] Tuning: Standard HTTP timeouts (ACTIVE=8s, IDLE=3s)")
    
    create_phase_marker(3)
    
    prompt_user(f"BẬT TẤN CÔNG: HTTP Flood (Hash)", "py [net.get(f'h{i}').cmd('python3 attack/http_flood.py http://10.0.0.10:8000 hash &') for i in range(9, 12)]")
    collect_data(3, target_samples=TARGET_SAMPLES_PER_CLASS // 2, description="Hash")
    prompt_user(f"DỪNG TẤN CÔNG: HTTP Flood (Hash)", cmd_attack_stop)
    print("[*] Đang dọn dẹp bộ đệm (chờ 3s)...")
    time.sleep(3)
    
    prompt_user(f"BẬT TẤN CÔNG: HTTP Flood (JSON)", "py [net.get(f'h{i}').cmd('python3 attack/http_flood.py http://10.0.0.10:8000 json &') for i in range(12, 15)]")
    collect_data(3, target_samples=TARGET_SAMPLES_PER_CLASS // 2, description="JSON")
    prompt_user(f"DỪNG TẤN CÔNG: HTTP Flood (JSON)", cmd_attack_stop)
    cleanup_all_markers()
    print("[*] Đang dọn dẹp bộ đệm (chờ 3s)...")
    time.sleep(3)

    # PHASE 4: Slowloris -> Đích: Web1 (10.0.0.11) 
    print("\n[PHASE 4️⃣ ] SLOWLORIS ATTACK - 10 min")
    print("[💡] Slowloris: Slow header transmission, bắt long-lived connections")
    print("[*] Tuning: Long timeouts (ACTIVE=30s, IDLE=15s)")
    
    # Tạo marker SLOWLORIS để batPack_v2 tăng IDLE_TIMEOUT lên 30s
    create_phase_marker(4)
    
    prompt_user(f"BẬT TẤN CÔNG: Slowloris", "py [net.get(f'h{i}').cmd('python3 attack/slowloris.py http://10.0.0.11:8000 &') for i in range(16, 21)]")
    collect_data(4, target_samples=TARGET_SAMPLES_PER_CLASS, health_check_url=None, description="Slowloris")
    prompt_user(f"DỪNG TẤN CÔNG: Slowloris", cmd_attack_stop)
    
    cleanup_all_markers()
    print("[*] Đang dọn dẹp bộ đệm (chờ 3s)...")
    time.sleep(3)

    print("\n" + "="*70)
    print(f"🎉 THÀNH CÔNG! Dataset 5 lớp đã sẵn sàng tại {OUTPUT_CSV}")
    print(f"[*] Tổng số mẫu dự kiến: {TARGET_SAMPLES_PER_CLASS * 4 + NORMAL_SAMPLES_TARGET:,}")
    print("="*70)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: 
        print("\n[!] Đã dừng chương trình thủ công.")
        sys.exit(0)
