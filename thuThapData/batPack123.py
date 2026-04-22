import errno
import json
import os
import time
import socket
import subprocess
import requests
from nfstream import NFStreamer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# --- CẤU HÌNH TỐI ƯU (UNIFIED FOR NORMAL + SLOWLORIS) ---
IFACE = os.environ.get("BATPACK_IFACE", "")
OUTPUT_FIFO_NORMAL = os.path.join(BASE_DIR, "zeek_stream.json")
OUTPUT_FIFO_SLOWLORIS = os.path.join(BASE_DIR, "zeek_stream_slowloris.json")
FLUSH_BATCH_SIZE = 50 # Xả lũ sau mỗi 50 luồng
FLUSH_INTERVAL = 1.0  # Hoặc sau mỗi 1 giây
RESTRICTED_PORTS = {22, 6633, 6653}
SLOWLORIS_HEALTH_URL = os.environ.get("SLOWLORIS_TARGET_URL", "http://127.0.0.1:8000")
WEB_RESTART_CMD = os.environ.get("WEB_RESTART_CMD", "").strip()

def _pick_attr(flow, *names, default=0):
    for name in names:
        if hasattr(flow, name):
            value = getattr(flow, name)
            if value is not None:
                return value
    return default

def _detect_iface():
    if IFACE:
        return IFACE
    
    try:
        nets = set(os.listdir("/sys/class/net"))
    except Exception:
        nets = set()

    # CHIẾN THUẬT L3 CUỐI CÙNG (Sau khi test diagnostic):
    # ✅ s6-eth1 = BEST: 99.7% filter pass, capture botnet + client
    #    - Backbone vào s6 (Web Server Switch)
    #    - Capture traffic từ s1-eth2 (botnet) + s1-eth3 (client)
    #    - Có cả reverse flow + attack flow
    # Fallback: s6-eth4, h82-eth1 (nếu s6-eth1 không có)
    preferred = ["s6-eth1", "s6-eth4", "h82-eth1", "s6-eth2", "s6-eth3"]
    
    for name in preferred:
        if name in nets:
            print(f"[BATPACK] Đã phát hiện cổng ưu tiên: {name}")
            return name
    
    # Fallback: tìm cổng s6
    for name in sorted(nets):
        if name.startswith("s6-eth"):
            return name
            
    return "s6-eth1"


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
        print("[BATPACK] WEB_RESTART_CMD chưa cấu hình, không thể restart tự động.")
        return False
    try:
        subprocess.run(WEB_RESTART_CMD, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[BATPACK] Đã gửi lệnh restart webserver tự động.")
        time.sleep(5)
        return True
    except Exception as e:
        print(f"[BATPACK] Lỗi khi restart webserver: {e}")
        return False


def _wait_for_target_alive(target_url, max_retry=3, interval=2):
    host, port = _parse_target_url(target_url)
    for attempt in range(1, max_retry + 1):
        if _is_target_alive(host, port):
            return True
        print(f"[BATPACK] Web target {host}:{port} chưa trả lời (attempt {attempt}/{max_retry}).")
        time.sleep(interval)
    # Nếu fail sau max_retry, prompt user để khởi động web
    print("\n" + "="*70)
    print("🚨 WEB TARGET KHÔNG PHẢN HỒI SAU 3 LẦN THỬ!")
    print("="*70)
    print(f"Web target {host}:{port} vẫn chưa trả lời.")
    print("Hãy khởi động web server bằng lệnh trong Mininet:")
    print("containernet> web1 sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000 &'")
    print("-" * 70)
    input("Sau khi khởi động xong, HÃY BẤM ENTER TẠI ĐÂY ĐỂ CHECK LẠI...")
    # Check lại sau khi user nhấn enter
    return _wait_for_target_alive(target_url, max_retry=3, interval=2)


def main():
    print(f"[BATPACK] 🎧 Đang lắng nghe cả 2 FIFO (normal + slowloris)...")
    print(f"[BATPACK] • Normal phases: {OUTPUT_FIFO_NORMAL}")
    print(f"[BATPACK] • Slowloris phase: {OUTPUT_FIFO_SLOWLORIS}")
    print(f"[BATPACK] • BASE_DIR: {BASE_DIR}")
    print(f"[BATPACK] • cwd: {os.getcwd()}")
    
    while True:
        # Auto-detect mode: kiểm tra xem FIFO nào đang được tạo
        mode = detect_capture_mode()
        print(f"[DEBUG] main loop: detected mode = {mode}")
        
        if mode == "SLOWLORIS":
            print(f"\n[BATPACK] 🟠 PHÁT HIỆN PHASE SLOWLORIS - Chuyển sang Slowloris Mode")
            capture_slowloris()
            
        elif mode == "NORMAL":
            print(f"\n[BATPACK] 🟢 PHÁT HIỆN PHASE BÌNH THƯỜNG/ATTACK - Chuyển sang Normal Mode")
            capture_normal()
        
        else:
            # Chờ generator tạo FIFO
            print(f"[BATPACK] ⏳ Chờ generator khởi tạo FIFO (có thể mất vài giây)...")
            time.sleep(1)

def _choose_marker(slowloris_marker, normal_marker):
    slow_exists = os.path.exists(slowloris_marker)
    normal_exists = os.path.exists(normal_marker)
    if slow_exists and normal_exists:
        slow_mtime = os.path.getmtime(slowloris_marker)
        normal_mtime = os.path.getmtime(normal_marker)
        print(f"[DEBUG] Cả hai marker tồn tại: slowloris mtime={slow_mtime}, normal mtime={normal_mtime}")
        if slow_mtime >= normal_mtime:
            try:
                os.remove(normal_marker)
                print("[BATPACK] Cả hai marker tồn tại; chọn .marker_slowloris và xóa .marker_normal.")
            except Exception:
                pass
            return "SLOWLORIS"
        else:
            try:
                os.remove(slowloris_marker)
                print("[BATPACK] Cả hai marker tồn tại; chọn .marker_normal và xóa .marker_slowloris.")
            except Exception:
                pass
            return "NORMAL"
    if slow_exists:
        return "SLOWLORIS"
    if normal_exists:
        return "NORMAL"
    return None


def detect_capture_mode():
    """Detect which mode to run based on marker files from auto_dataset_generator"""
    slowloris_marker = os.path.join(BASE_DIR, ".marker_slowloris")
    normal_marker = os.path.join(BASE_DIR, ".marker_normal")
    
    now = time.time()
    print(f"[DEBUG] detect_capture_mode called at {now} cwd={os.getcwd()} BASE_DIR={BASE_DIR}")
    for marker in [slowloris_marker, normal_marker]:
        if os.path.exists(marker):
            mtime = os.path.getmtime(marker)
            if now - mtime > 60:  # 1 minute
                print(f"[BATPACK] Removing old marker: {marker} (mtime={mtime})")
                os.remove(marker)
    
    slow_exists = os.path.exists(slowloris_marker)
    normal_exists = os.path.exists(normal_marker)
    print(f"[DEBUG] Checking markers: slowloris={slow_exists}, normal={normal_exists}")
    if slow_exists:
        print(f"[DEBUG] slowloris mtime={os.path.getmtime(slowloris_marker)}")
    if normal_exists:
        print(f"[DEBUG] normal mtime={os.path.getmtime(normal_marker)}")
    choice = _choose_marker(slowloris_marker, normal_marker)
    if choice:
        print(f"[DEBUG] Chose mode: {choice}")
        return choice
    
    # Đợi xem marker nào được tạo
    print(f"[DEBUG] Sleeping 1s...")
    time.sleep(1.0)
    slow_exists = os.path.exists(slowloris_marker)
    normal_exists = os.path.exists(normal_marker)
    print(f"[DEBUG] After sleep: slowloris={slow_exists}, normal={normal_exists}")
    if slow_exists:
        print(f"[DEBUG] slowloris mtime={os.path.getmtime(slowloris_marker)}")
    if normal_exists:
        print(f"[DEBUG] normal mtime={os.path.getmtime(normal_marker)}")
    choice = _choose_marker(slowloris_marker, normal_marker)
    print(f"[DEBUG] Final choice: {choice}")
    return choice


def _marker_change_detected(current_mode):
    if current_mode == "NORMAL":
        return os.path.exists(os.path.join(BASE_DIR, ".marker_slowloris"))
    if current_mode == "SLOWLORIS":
        return os.path.exists(os.path.join(BASE_DIR, ".marker_normal"))
    return False


def _open_fifo_writer(path, current_mode, timeout=0.5):
    while True:
        # Trong lúc đứng chờ FIFO mở, thỉnh thoảng ngó xem có lệnh chuyển Phase không
        if _marker_change_detected(current_mode):
            return None  # Trả về None để báo hiệu phải đổi Mode
            
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            return os.fdopen(fd, "w", buffering=1)
        except OSError as e:
            if e.errno in (errno.ENXIO, errno.EWOULDBLOCK):
                time.sleep(timeout)
                continue
            raise

def capture_normal():
    """Capture normal + attack traffic (UDP, SYN, HTTP, Normal)"""
    # Reset + Create FIFO
    if os.path.exists(OUTPUT_FIFO_NORMAL):
        try: os.remove(OUTPUT_FIFO_NORMAL)
        except: pass
    
    try:
        os.mkfifo(OUTPUT_FIFO_NORMAL)
        print(f"[BATPACK] ✅ Tạo Normal FIFO: {OUTPUT_FIFO_NORMAL}")
    except OSError:
        pass

    iface = _detect_iface()
    print(f"[BATPACK] 🖧 Interface: {iface} (timeout: 1-5s)")
    
    # NFStreamer với timeout NGẮN cho normal/attack (kết thúc nhanh)
    streamer = NFStreamer(
        source=iface,
        promiscuous_mode=True,
        idle_timeout=1,        # Ngắn
        active_timeout=5,      # Ngắn
        accounting_mode=0,     
        n_dissections=20,
        statistical_analysis=True
    )

    print(f"[BATPACK] 📡 Đang thu thập (Normal Mode)...")
    
    try:
        reconnect_count = 0
        while True:
            try:
                if _marker_change_detected("NORMAL"):
                    print("[BATPACK] Phát hiện marker Slowloris mới trước khi mở FIFO, dừng Normal để chuyển phase...")
                    break
                try:
                    # Gửi thêm tham số "NORMAL"
                    f = _open_fifo_writer(OUTPUT_FIFO_NORMAL, "NORMAL")
                    if f is None:
                        print("[BATPACK] Phát hiện marker Slowloris trong lúc chờ FIFO, ngắt Normal để chuyển phase ngay!")
                        break # Phá vỡ vòng lặp chờ để ra ngoài chuyển Mode
                except OSError:
                    if reconnect_count == 0:
                        print(f"[BATPACK] ⏳ Chờ reader cho {OUTPUT_FIFO_NORMAL}...")
                    reconnect_count += 1
                    time.sleep(1)
                    continue

                with f:
                    batch_data = []
                    last_flush = time.time()
                    reconnect_count = 0
                    last_recorded_state = {}

                    for flow in streamer:
                        if _marker_change_detected("NORMAL"):
                            print("[BATPACK] Phát hiện marker Slowloris mới, dừng Normal để chuyển phase...")
                            break

                        # Lọc traffic rác/nội bộ
                        if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                            continue
                        if flow.src_port in RESTRICTED_PORTS or flow.dst_port in RESTRICTED_PORTS:
                            continue
                        if flow.protocol == 1:
                            continue

                        flow_id = f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}"
                        current_state = (flow.bidirectional_packets, flow.bidirectional_bytes)
                        
                        if flow_id in last_recorded_state and last_recorded_state[flow_id] == current_state:
                            continue 
                        
                        last_recorded_state[flow_id] = current_state

                        # --- FEATURE ENGINEERING ---
                        duration_sec = flow.bidirectional_duration_ms / 1000.0
                        if duration_sec <= 0: duration_sec = 0.001
                        
                        conn_state = 0
                        if flow.protocol == 6:
                            conn_state = 1 if flow.bidirectional_packets >= 3 else 0
                        elif flow.protocol == 17:
                            conn_state = 2
                        
                        l7_proto = 0
                        app_name = str(_pick_attr(flow, "application_name", default="")).upper()
                        if "HTTP" in app_name: l7_proto = 1
                        elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name: l7_proto = 2
                        elif "DNS" in app_name: l7_proto = 3
                        elif "OPENFLOW" in app_name: l7_proto = 5

                        src_bytes = _pick_attr(flow, "src2dst_bytes", "src_to_dst_bytes", default=0)
                        dst_bytes = _pick_attr(flow, "dst2src_bytes", "dst_to_src_bytes", default=0)
                        src_packets = _pick_attr(flow, "src2dst_packets", "src_to_dst_packets", default=0)
                        dst_packets = _pick_attr(flow, "dst2src_packets", "dst_to_src_packets", default=0)
                        
                        is_weird = 0
                        if src_packets > 10 and dst_packets == 0:
                            is_weird = 1
                        elif src_packets > 100 and (src_packets / max(1, dst_packets)) > 50:
                            is_weird = 1

                        data = {
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
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
                        
                        batch_data.append(json.dumps(data))

                        now = time.time()
                        if len(batch_data) >= FLUSH_BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL:
                            try:
                                f.write("\n".join(batch_data) + "\n")
                                f.flush()
                                batch_data = []
                                last_flush = now
                            except (BrokenPipeError, IOError) as e:
                                if reconnect_count == 0:
                                    print(f"[BATPACK] ⏸️  Tạm dừng Normal (Phase chuyển)...")
                                reconnect_count += 1
                                break
                                    
            except (BrokenPipeError, IOError) as e:
                if reconnect_count == 0:
                    print(f"[BATPACK] ⏳ Chờ Normal FIFO mở lại...")
                reconnect_count += 1
                time.sleep(2)
                continue
                
    except KeyboardInterrupt:
        print("[BATPACK] Dừng capture Normal.")
    finally:
        if os.path.exists(OUTPUT_FIFO_NORMAL):
            try:
                os.remove(OUTPUT_FIFO_NORMAL)
            except:
                pass

def capture_slowloris():
    """Capture Slowloris attack traffic (kết nối lâu)"""
    # Reset + Create FIFO
    if os.path.exists(OUTPUT_FIFO_SLOWLORIS):
        try: os.remove(OUTPUT_FIFO_SLOWLORIS)
        except: pass
    
    try:
        os.mkfifo(OUTPUT_FIFO_SLOWLORIS)
        print(f"[BATPACK] ✅ Tạo Slowloris FIFO: {OUTPUT_FIFO_SLOWLORIS}")
    except OSError:
        pass

    # if not _wait_for_target_alive(SLOWLORIS_HEALTH_URL):
    #     print("[BATPACK] Web target Slowloris không sống, tạm dừng Slowloris capture.")
    #     return

    iface = _detect_iface()
    print(f"[BATPACK] 🖧 Interface: {iface} (timeout: 30-120s)")
    
    # NFStreamer với timeout DÀI cho slowloris (kết nối ngâm lâu)
    streamer = NFStreamer(
        source=iface,
        promiscuous_mode=True,
        idle_timeout=30,       # DÀI (Slowloris ngâm kết nối)
        active_timeout=120,    # DÀI (kéo dài 60-120s)
        accounting_mode=0,     
        n_dissections=20,
        statistical_analysis=True
    )

    print(f"[BATPACK] 📡 Đang thu thập (Slowloris Mode)...")
    
    try:
        reconnect_count = 0
        while True:
            try:
                if _marker_change_detected("SLOWLORIS"):
                    print("[BATPACK] Phát hiện marker Normal mới trước khi mở FIFO, dừng Slowloris để chuyển phase...")
                    break

                try:
                    # Gửi thêm tham số "SLOWLORIS"
                    f = _open_fifo_writer(OUTPUT_FIFO_SLOWLORIS, "SLOWLORIS")
                    if f is None:
                        print("[BATPACK] Phát hiện marker Normal trong lúc chờ FIFO, ngắt Slowloris để chuyển phase ngay!")
                        break # Phá vỡ vòng lặp chờ để ra ngoài chuyển Mode
                except OSError:
                    if reconnect_count == 0:
                        print(f"[BATPACK] ⏳ Chờ reader cho {OUTPUT_FIFO_SLOWLORIS}...")
                    reconnect_count += 1
                    time.sleep(1)
                    continue

                with f:
                    batch_data = []
                    last_flush = time.time()
                    reconnect_count = 0
                    last_recorded_state = {}
                    last_health_check = time.time()
                    health_check_interval = 20.0

                    for flow in streamer:
                        if _marker_change_detected("SLOWLORIS"):
                            print("[BATPACK] Phát hiện marker Normal mới, dừng Slowloris để chuyển phase...")
                            break

                        # if time.time() - last_health_check >= health_check_interval:
                        #     if not _wait_for_target_alive(SLOWLORIS_HEALTH_URL, max_retry=1, interval=1):
                        #         print("[BATPACK] Web target Slowloris đã sập trong quá trình thu. Dừng Slowloris capture.")
                        #         break
                        #     last_health_check = time.time()

                        # Lọc traffic rác/nội bộ
                        if flow.src_ip.startswith('127.') or flow.src_ip == '0.0.0.0' or ':' in flow.src_ip:
                            continue
                        if flow.src_port in RESTRICTED_PORTS or flow.dst_port in RESTRICTED_PORTS:
                            continue
                        if flow.protocol == 1:
                            continue

                        flow_id = f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}"
                        current_state = (flow.bidirectional_packets, flow.bidirectional_bytes)
                        
                        if flow_id in last_recorded_state and last_recorded_state[flow_id] == current_state:
                            continue 
                        
                        last_recorded_state[flow_id] = current_state

                        # --- FEATURE ENGINEERING (khớp batPack123) ---
                        duration_sec = flow.bidirectional_duration_ms / 1000.0
                        if duration_sec <= 0: duration_sec = 0.001
                        
                        conn_state = 0
                        if flow.protocol == 6:
                            conn_state = 1 if flow.bidirectional_packets >= 3 else 0
                        elif flow.protocol == 17:
                            conn_state = 2
                        
                        l7_proto = 0
                        app_name = str(_pick_attr(flow, "application_name", default="")).upper()
                        if "HTTP" in app_name: l7_proto = 1
                        elif "TLS" in app_name or "SSL" in app_name or "QUIC" in app_name: l7_proto = 2
                        elif "DNS" in app_name: l7_proto = 3
                        elif "OPENFLOW" in app_name: l7_proto = 5

                        src_bytes = _pick_attr(flow, "src2dst_bytes", "src_to_dst_bytes", default=0)
                        dst_bytes = _pick_attr(flow, "dst2src_bytes", "dst_to_src_bytes", default=0)
                        src_packets = _pick_attr(flow, "src2dst_packets", "src_to_dst_packets", default=0)
                        dst_packets = _pick_attr(flow, "dst2src_packets", "dst_to_src_packets", default=0)
                        
                        is_weird = 0
                        if duration_sec > 10 and src_packets < 20 and dst_packets < 20:
                            is_weird = 1
                        elif src_packets > 10 and dst_packets == 0:
                            is_weird = 1

                        data = {
                            "src_ip": flow.src_ip,
                            "dst_ip": flow.dst_ip,
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
                        
                        batch_data.append(json.dumps(data))

                        now = time.time()
                        if len(batch_data) >= FLUSH_BATCH_SIZE or (now - last_flush) >= FLUSH_INTERVAL:
                            try:
                                f.write("\n".join(batch_data) + "\n")
                                f.flush()
                                batch_data = []
                                last_flush = now
                            except (BrokenPipeError, IOError) as e:
                                if reconnect_count == 0:
                                    print(f"[BATPACK] ⏸️  Tạm dừng Slowloris (Phase chuyển)...")
                                reconnect_count += 1
                                break
                                    
            except (BrokenPipeError, IOError) as e:
                if reconnect_count == 0:
                    print(f"[BATPACK] ⏳ Chờ Slowloris FIFO mở lại...")
                reconnect_count += 1
                time.sleep(2)
                continue
                
    except KeyboardInterrupt:
        print("[BATPACK] Dừng capture Slowloris.")
    finally:
        if os.path.exists(OUTPUT_FIFO_SLOWLORIS):
            try:
                os.remove(OUTPUT_FIFO_SLOWLORIS)
            except:
                pass

if __name__ == "__main__":
    main()
