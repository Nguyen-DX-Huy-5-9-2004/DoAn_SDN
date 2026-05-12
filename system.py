#!/usr/bin/python3
from requests.auth import HTTPBasicAuth

import os
import shlex
import shutil
import socket
import threading
import time
import subprocess
import requests

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel
from mininet.cli import CLI

from topology.research_topo import ResearchTopo

from mininet.net import Containernet
from mininet.node import Docker, OVSSwitch
from mininet.link import TCLink, Intf

# --- CẤU HÌNH IDS NÂNG CẤP ---
# Temporal Consistency Monitoring: Lưu trữ lịch sử dự đoán của từng IP
IP_PREDICTION_HISTORY = {} # {ip: [label1, label2, ...]}
HISTORY_WINDOW = 5         # Kiểm tra 5 chuỗi liên tiếp
DROP_THRESHOLD = 3         # Nếu 3/5 chuỗi là Attack -> Thực hiện DROP mạnh tay

# Thư mục gốc dự án (tránh hard-code /home/tgf/... khi chạy máy khác)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def _pick_gui_browser():
    for name in (
        "microsoft-edge-stable",
        "google-chrome-stable",
        "chromium-browser",
        "chromium",
        "firefox",
    ):
        path = shutil.which(name)
        if path:
            return path
    return shutil.which("xdg-open")


def _chromium_family(basename):
    return basename in (
        "microsoft-edge-stable",
        "google-chrome-stable",
        "chromium-browser",
        "chromium",
        "chrome",
        "brave-browser",
    )


def _build_browser_argv(browser: str, url: str, *, isolated_profile: bool):
    """isolated_profile: profile riêng tránh khóa với Edge/Chrome đang mở; cần khi spawn từ script/root."""
    base = os.path.basename(browser)
    argv = [browser]
    if _chromium_family(base):
        argv.append("--no-sandbox")
        if isolated_profile:
            tag = (os.environ.get("SUDO_USER") or str(os.geteuid())).replace("/", "_")
            argv.extend(
                [
                    "--disable-dev-shm-usage",
                    f"--user-data-dir=/tmp/doan_sdn_browser_{tag}",
                    "--new-window",
                ]
            )
        argv.append(url)
    elif base == "firefox" and isolated_profile:
        argv.extend(["-no-remote", "-private-window", url])
    else:
        argv.append(url)
    return argv


# Tên container Containernet (dnameprefix + tên node)
DOCKER_WEB1_CNAME = "mn.web1"
DOCKER_PROXY1_CNAME = "mn.proxy1"
WEB1_HOST_PORT = 8000
WEB1_CONTAINER_DJANGO_PORT = 8000  # FIXED: Match attack/normal scripts targeting :8000
PROXY1_HOST_HTTPS_PORT = 8443

_web1_proxy_lock = threading.Lock()
_web1_proxy_started = False
_proxy1_https_proxy_lock = threading.Lock()
_proxy1_https_proxy_started = False


def _django_on_localhost_ok():
    try:
        r = requests.get(f"http://127.0.0.1:{WEB1_HOST_PORT}/", timeout=5)
        return r.status_code < 600
    except requests.RequestException:
        return False


def _relay_web1_via_docker_exec(client: socket.socket, container: str, django_port: int) -> None:
    try:
        proc = subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                container,
                "python3",
                "-u",
                "/app/tunnel_peer.py",
                str(django_port),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except OSError:
        client.close()
        return

    def client_to_proc():
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                try:
                    proc.stdin.write(data)
                    proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    break
        except (ConnectionResetError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def proc_to_client():
        try:
            # Use os.read on the fileno to avoid blocking for a full buffer
            # and to avoid AttributeError: '_io.FileIO' object has no attribute 'read1'
            fd = proc.stdout.fileno()
            while True:
                data = os.read(fd, 65536)
                if not data:
                    break
                try:
                    client.sendall(data)
                except (BrokenPipeError, OSError):
                    break
        except (ConnectionResetError, OSError):
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=client_to_proc, daemon=True)
    t.start()
    try:
        proc_to_client()
    finally:
        t.join(timeout=2)
        proc.terminate()
        try:
            client.close()
        except OSError:
            pass


def _relay_proxy1_https_via_docker_exec(client: socket.socket, container: str) -> None:
    """Chuyển tiếp TCP thô từ localhost:8443 vào proxy1:443."""
    try:
        proc = subprocess.Popen(
            ["docker", "exec", "-i", container, "sh", "-c", "nc 127.0.0.1 443"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
    except OSError:
        client.close()
        return

    def client_to_proc():
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                proc.stdin.write(data)
                proc.stdin.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def proc_to_client():
        try:
            fd = proc.stdout.fileno()
            while True:
                # Use os.read on the fileno to avoid blocking for a full buffer
                data = os.read(fd, 65536)
                if not data:
                    break
                client.sendall(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=client_to_proc, daemon=True)
    t.start()
    try:
        proc_to_client()
    finally:
        t.join(timeout=2)
        proc.terminate()
        try:
            client.close()
        except OSError:
            pass


def _ensure_web1_localhost_proxy():
    """Khi Docker port_publish không tới host (web1 chỉ có veth OVS), lắng nghe 127.0.0.1 và chuyển tiếp qua docker exec."""
    global _web1_proxy_started
    with _web1_proxy_lock:
        if _web1_proxy_started:
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", WEB1_HOST_PORT)) # Listen on all interfaces to be safe
        except OSError as e:
            print(
                f"[!] Không bind proxy tại 127.0.0.1:{WEB1_HOST_PORT} ({e}). "
                "Thử đóng tiến trình đang giữ cổng hoặc mở tay http://10.0.0.10:8000 từ topo."
            )
            return
        srv.listen(128)
        _web1_proxy_started = True

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            threading.Thread(
                target=_relay_web1_via_docker_exec,
                args=(conn, DOCKER_WEB1_CNAME, WEB1_CONTAINER_DJANGO_PORT),
                daemon=True,
            ).start()

    threading.Thread(target=accept_loop, daemon=True).start()


def _ensure_proxy1_https_localhost_proxy():
    """Expose HTTPS proxy ra máy host tại 127.0.0.1:8443."""
    global _proxy1_https_proxy_started
    with _proxy1_https_proxy_lock:
        if _proxy1_https_proxy_started:
            return
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", PROXY1_HOST_HTTPS_PORT))
        except OSError as e:
            print(
                f"[!] Không bind HTTPS proxy tại 127.0.0.1:{PROXY1_HOST_HTTPS_PORT} ({e}). "
                "Mở tay trong topo qua https://10.0.0.10 hoặc giải phóng cổng local."
            )
            return
        srv.listen(128)
        _proxy1_https_proxy_started = True

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            threading.Thread(
                target=_relay_proxy1_https_via_docker_exec,
                args=(conn, DOCKER_PROXY1_CNAME),
                daemon=True,
            ).start()

    threading.Thread(target=accept_loop, daemon=True).start()


def _spawn_browser_on_desktop(url: str) -> bool:
    """Mở browser trong session desktop (không qua netns h60) — tránh Edge “có icon nhưng không bật cửa sổ”."""
    browser = _pick_gui_browser()
    if not browser:
        return False
    display = os.environ.get("DISPLAY", ":0")
    xauth = os.environ.get("XAUTHORITY", "")
    argv = _build_browser_argv(browser, url, isolated_profile=True)
    env = os.environ.copy()
    env["DISPLAY"] = display
    if xauth:
        env["XAUTHORITY"] = xauth
    sudo_user = os.environ.get("SUDO_USER")
    try:
        if sudo_user and sudo_user not in ("root", ""):
            cmd = ["sudo", "-u", sudo_user, "-E", *argv]
        else:
            cmd = argv
        subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except OSError:
        return False


# MAC khớp onos/netcfg.json — phải truyền rõ vào addDocker để autoSetMacs=True không ghi đè (00:21, 00:22).
DOCKER_WEB1_MAC = "00:00:00:00:00:10"
DOCKER_PROXY1_MAC = "00:00:00:00:00:11"
DOCKER_DB1_MAC = "00:00:00:00:00:20"


class IpCompatIntf(Intf):
    """Intf dùng iproute2 thay cho ifconfig (Docker slim/alpine thường không có net-tools)."""

    def ifconfig(self, *args):  # noqa: A003 — giữ tên API Mininet
        if not args:
            return self.cmd("ip", "link", "show", "dev", self.name)
        if args == ("up",):
            return self.cmd("ip", "link", "set", self.name, "up")
        if args and args[0] == "down":
            return self.cmd("ip", "link", "set", self.name, "down")
        if len(args) >= 3 and args[0] == "hw" and args[1] == "ether":
            return self.cmd("ip", "link", "set", self.name, "address", args[2])
        return self.cmd("ifconfig", self.name, *args)


class StableOVSSwitch(OVSSwitch):
    """OVS với reconnectms cao hơn để giảm link flapping khi mất kết nối tạm thời với ONOS."""
    def __init__(self, name, **kwargs):
        kwargs.setdefault('reconnectms', 5000)  # 5s thay vì mặc định ~1s
        kwargs.setdefault('protocols', 'OpenFlow13')
        OVSSwitch.__init__(self, name, **kwargs)

ONOS_BASE = "http://localhost:8181/onos/v1"
AUTH = ("onos", "rocks")

EXPECTED_SWITCHES = 6
EXPECTED_HOSTS = 35

def wait_for_onos(timeout=120):
    url = "http://127.0.0.1:8181/onos/v1/applications"
    auth = HTTPBasicAuth('onos', 'rocks')
    start_time = time.time()
    
    print("[SYSTEM] Đang chờ ONOS REST API sẵn sàng...")
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, auth=auth, timeout=2)
            if response.status_code == 200:
                print(f"[SYSTEM] ONOS đã online sau {int(time.time() - start_time)} giây!")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
        print(".", end="", flush=True)
    
    print("\n[!] Quá thời gian chờ ONOS. Vui lòng kiểm tra container!")
    return False

# -------------------------------------------------
# CLEAN
# -------------------------------------------------

def clean_mininet():

    print("[SYSTEM] Cleaning old Mininet environment...")

    os.system("mn -c > /dev/null 2>&1")

    time.sleep(2)

    print("[SYSTEM] Environment ready")

# -------------------------------------------------
# WAIT DEVICES
# -------------------------------------------------

def wait_devices():
    print(f"[SYSTEM] Đang chờ khám phá {EXPECTED_SWITCHES} switches...")
    while True:
        try:
            r = requests.get(f"{ONOS_BASE}/devices", auth=AUTH, timeout=2)
            if r.status_code == 200:
                devices = r.json().get("devices", [])
                if len(devices) >= EXPECTED_SWITCHES:
                    print(f"[OK] Đã nhận diện đủ {len(devices)} switches.")
                    return
            print(f".", end="", flush=True)
        except Exception:
            pass
        time.sleep(2)


# -------------------------------------------------
# WAIT HOSTS
# -------------------------------------------------

def wait_hosts(timeout=30):

    print("Waiting host discovery")

    start = time.time()

    while True:

        r = requests.get(
            f"{ONOS_BASE}/hosts",
            auth=AUTH
        )

        hosts = r.json()["hosts"]

        print(f"Hosts discovered: {len(hosts)}/{EXPECTED_HOSTS}")

        if len(hosts) >= EXPECTED_HOSTS:
            print("All hosts discovered")
            return

        if time.time() - start > timeout:
            print("Host discovery timeout")
            return

        time.sleep(2)


# -------------------------------------------------
# ENABLE APPS
# -------------------------------------------------

def enable_apps():

    apps = [
        "org.onosproject.openflow",
        "org.onosproject.hostprovider",
        "org.onosproject.lldpprovider",
        "org.onosproject.fwd",
        "org.onosproject.proxyarp",
        "org.onosproject.gui"
    ]

    for app in apps:

        url = f"{ONOS_BASE}/applications/{app}/active"

        try:

            requests.post(url, auth=AUTH)
            print("Enabled:", app)

        except:
            print("Failed:", app)


# -------------------------------------------------
# DOCKER / CONTAINERNET — cấu hình dataplane (không dùng ifconfig)
# -------------------------------------------------
def _ensure_iproute2_web1(web1) -> None:
    """Kiểm tra `ip`/`ping` trong web1 bằng cách gọi trực tiếp lệnh."""
    # Gọi thẳng lệnh 'ip -V' thay vì thông qua bash phức tạp
    check_ip = web1.cmd("ip -V 2>&1").strip()
    
    # Nếu kết quả trả về có chứa chữ 'ip utility' hoặc 'iproute2' là đã cài đặt thành công
    if "ip utility" in check_ip.lower() or "iproute2" in check_ip.lower():
        print("[DOCKER] web1: đã có `ip` và `ping`.")
        return
        
    print(
        "[DOCKER] web1: THIẾU `ip` hoặc `ping`.\n"
        "  - Hãy build image web1 trước khi chạy lab:\n"
        "    docker build -t doan_sdn_web1:py39 -f docker/web1/Dockerfile .\n"
        "  - Hoặc kiểm tra kết nối Internet/DNS trong Docker."
    )


def _ensure_iproute2_db1(db1) -> None:
    """Đủ lệnh `ip`/`ip address` tương thích Mininet (BusyBox ip thiếu tùy chọn)."""
    print("[DOCKER] db1: apk add iproute2...")
    log = db1.cmd(
        "sh -c 'timeout 15 apk add --no-cache iproute2 2>&1; command -v ip || true'"
    ).strip()
    tail = log[-200:] if len(log) > 200 else log
    print(f"[DOCKER] db1: {tail}")


def configure_local_mirroring(net) -> None:
    """Mirror TOÀN BỘ lưu lượng đi qua s6 sang h82-eth1."""
    s6 = net.get("s6")
    h82 = net.get("h82")
    
    # Tìm đúng cổng của h82 trên s6 (link phụ không mang IP)
    s6_h82_intf = None
    h82_default = h82.defaultIntf().name if h82.defaultIntf() else ""
    for s6_i, h82_i in s6.connectionsTo(h82):
        if h82_i.name != h82_default:
            s6_h82_intf = s6_i
            break
            
    if not s6_h82_intf:
        print("[MIRROR] LỖI: Không tìm thấy cổng mirror trên s6!")
        return

    # Mirror TOÀN BỘ các cổng trên s6 (trừ cổng output mirror) sang h82-eth1
    # Điều này đảm bảo bắt được IP gốc của Client trước khi qua Proxy
    all_ports = [p.name for p in s6.intfList() if p.name != "lo" and p.name != s6_h82_intf.name]
    port_ids = ",".join([f"@{p.replace('-', '_')}" for p in all_ports])
    
    cmd_parts = []
    for p in all_ports:
        cmd_parts.append(f"-- --id=@{p.replace('-', '_')} get Port {p}")
    
    final_cmd = (
        "ovs-vsctl " + " ".join(cmd_parts) +
        f" -- --id=@m create Mirror name=s6_all_mirror select-src-port={port_ids} select-dst-port={port_ids} output-port=@{s6_h82_intf.name.replace('-', '_')} "
        "-- clear Bridge s6 mirrors -- set Bridge s6 mirrors=@m"
    )
    
    out = s6.cmd(final_cmd).strip()
    if out:
        print(f"[MIRROR] {out}")
    print(f"[MIRROR] Đã bật mirror TOÀN BỘ s6 -> {s6_h82_intf.name}")


def _debug_docker_iface(net, hostname: str) -> None:
    h = net.get(hostname)
    intfs = [i.name for i in h.intfList() if i.name != "lo"]
    di = h.defaultIntf()
    print(
        f"[DOCKER-DEBUG] {hostname}: interfaces={intfs} default={getattr(di, 'name', None)} "
        f"IP()={h.IP()!r} MAC()={h.MAC()!r}"
    )


def _finish_docker_dataplane(net, hostname: str, ipv4: str) -> None:
    """Bật cổng Mininet trong container bằng iproute2 và gán IP (model Intf + kernel)."""
    h = net.get(hostname)
    intf = h.defaultIntf()
    if not intf:
        print(f"[DOCKER-DEBUG] {hostname}: LỖI — không có defaultIntf")
        return
    # Không dùng `ip -br` — BusyBox không hỗ trợ -br.
    show = h.cmd(f"ip link show dev {intf.name} 2>&1 | head -n1").strip()
    print(f"[DOCKER-DEBUG] {hostname}: trước UP: {show[:180]}")
    up_out = h.cmd(f"ip link set {intf.name} up 2>&1").strip()
    if up_out:
        print(f"[DOCKER-DEBUG] {hostname}: ip link up → {up_out}")
    h.setIP(f"{ipv4}/24", intf=intf.name)
    ker = h.cmd(
        f"ip -4 addr show dev {intf.name} 2>&1 | sed -n 's/.*inet //p' | head -n1"
    ).strip()
    print(f"[DOCKER-DEBUG] {hostname}: IP trong kernel trên {intf.name}: {ker or '(trống — lỗi)'}")
    _debug_docker_iface(net, hostname)


# -------------------------------------------------
# START NETWORK
# -------------------------------------------------
def apply_ips_decision(net, src_ip, label, confidence):
    """
    Giám sát tính nhất quán theo thời gian (Temporal Consistency Monitoring)
    Thực hiện lệnh DROP thực tế trên hạ tầng mạng L3.
    """
    global IP_PREDICTION_HISTORY
    
    label_map = {1: "UDP Flood", 2: "SYN Flood", 3: "HTTP Flood", 4: "Slowloris"}
    
    if label == 0: # Normal
        if src_ip in IP_PREDICTION_HISTORY:
            # Nếu IP này từng bị nghi ngờ nhưng giờ đã bình thường -> Xóa lịch sử (Giảm False Positive)
            del IP_PREDICTION_HISTORY[src_ip]
        return "PASS"

    # Lưu lịch sử dự đoán
    if src_ip not in IP_PREDICTION_HISTORY:
        IP_PREDICTION_HISTORY[src_ip] = []
    
    IP_PREDICTION_HISTORY[src_ip].append(label)
    if len(IP_PREDICTION_HISTORY[src_ip]) > HISTORY_WINDOW:
        IP_PREDICTION_HISTORY[src_ip].pop(0)

    # Kiểm tra sự nhất quán: DDoS thật sự là một dòng chảy liên tục
    attack_count = sum(1 for l in IP_PREDICTION_HISTORY[src_ip] if l != 0)
    
    if attack_count >= DROP_THRESHOLD:
        print(f"\n[IPS] � PHÁT HIỆN TẤN CÔNG NHẤT QUÁN! IP: {src_ip} | Loại: {label_map.get(label)} | Vi phạm: {attack_count}/{HISTORY_WINDOW}")
        
        # --- THỰC THI LỆNH DROP (MẠNG L3) ---
        # Chặng 1: DROP tại s6 (Cửa ngõ Gateway)
        # Sử dụng ovs-ofctl để đẩy Flow Rule trực tiếp vào Switch s6
        s6 = net.get('s6')
        if s6:
            # Lệnh: Nếu src_ip là kẻ tấn công -> DROP ngay lập tức
            # priority=1000 (cao nhất để ghi đè các luật Forwarding thông thường)
            drop_cmd = f"ovs-ofctl add-flow s6 'priority=1000,ip,nw_src={src_ip},actions=drop'"
            s6.cmd(drop_cmd)
            
            # Lưu vết vào log hệ thống
            with open("/tmp/ips_actions.log", "a") as f:
                f.write(f"[{time.ctime()}] BLOCKED {src_ip} on s6 - Reason: Consistent {label_map.get(label)}\n")
            
            print(f"[IPS] 🛡️ Đã thực thi lệnh DROP cho IP {src_ip} tại Gateway Switch (s6).")
            return "DROP_EXECUTED"
    
    return "MONITORING"

def start_network():
    topo = ResearchTopo()
    
    print("*** Dọn dẹp môi trường cũ...")
    subprocess.call(
        ["docker", "rm", "-f", "web1", "db1", "proxy1"],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    os.system("sudo ip link show | grep -E '^[0-9]+:' | grep -E '(s[0-9]|h[0-9]|web|db)' | awk '{print $2}' | sed 's/:$//' | while read iface; do sudo ip link del $iface 2>/dev/null; done")
    os.system("sudo ovs-vsctl --if-exists del-br s1 -- --if-exists del-br s2 -- --if-exists del-br s3 -- --if-exists del-br s4 -- --if-exists del-br s5 -- --if-exists del-br s6 2>/dev/null")
    time.sleep(2)

    # TUYỆT CHIÊU 1: DÙNG StableOVSSwitch ĐỂ KHỞI TẠO OF1.3 NGAY TỪ ĐẦU
    net = Containernet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="172.17.0.2", port=6653),
        switch=StableOVSSwitch,  # Đã sửa lại thành StableOVSSwitch
        autoSetMacs=True,
        autoStaticArp=True
    )

    print("*** Đang thêm các máy chủ Docker vào hệ thống...")
    web1 = net.addDocker(
        'web1',
        ip='10.0.0.11',
        mac=DOCKER_WEB1_MAC,
        dimage="doan_sdn_web1:py39",
        mem_limit="512m",
        cpu_quota=75000,  #CPU 75% để không bị chết khi bị tấn công
        volumes=[f"{PROJECT_ROOT}/services/my_web_app:/app"],
        dcmd="tail -f /dev/null",
    )
    proxy1 = net.addDocker(
        "proxy1",
        ip="10.0.0.10",
        mac=DOCKER_PROXY1_MAC,
        dimage="doan_sdn_proxy1:latest",
        mem_limit="128m",
        cpu_quota=20000,
        volumes=[
            f"{PROJECT_ROOT}/docker/proxy/nginx.conf:/etc/nginx/nginx.conf:ro",
            f"{PROJECT_ROOT}/docker/proxy/certs:/etc/nginx/certs:ro",
        ],
        dcmd="/bin/bash",
    )
    db1 = net.addDocker(
        'db1',
        ip='10.0.0.20',
        mac=DOCKER_DB1_MAC,
        dimage="postgres:15-alpine",
        mem_limit="512m",
        cpu_quota=50000,
        environment={
            "POSTGRES_PASSWORD": "root",
            "POSTGRES_USER": "postgres",
            "POSTGRES_DB": "postgres",
            "POSTGRES_HOST_AUTH_METHOD": "trust",
        },
        dcmd="/usr/local/bin/docker-entrypoint.sh postgres",
    )

    _ensure_iproute2_web1(web1)
    _ensure_iproute2_db1(db1)

    s5 = net.get('s5')
    s6 = net.get('s6')
    h82 = net.get("h82")
    # MAC cố định trên veth ngay khi tạo (khớp onos/netcfg.json). Đổi MAC sau khi mạng đã chạy
    # khiến ARP cache / ARP tĩnh trỏ nhầm MAC cũ => ping tới web1/db1 thất bại, ONOS học host sai.
    net.addLink(web1, s6, addr1=DOCKER_WEB1_MAC, cls1=IpCompatIntf)
    net.addLink(proxy1, s6, addr1=DOCKER_PROXY1_MAC, cls1=IpCompatIntf)
    net.addLink(db1, s5, addr1=DOCKER_DB1_MAC, cls1=IpCompatIntf)
    # Link phụ dành riêng cho mirror, không mang IP để không phá đường truyền chính của h82.
    net.addLink(h82, s6)
    print("*** Docker: gán IP và bật cổng (tránh ifconfig trong image)...")
    _finish_docker_dataplane(net, "web1", "10.0.0.11")
    _finish_docker_dataplane(net, "proxy1", "10.0.0.10")
    _finish_docker_dataplane(net, "db1", "10.0.0.20")
    h82.cmd("ip link set h82-eth1 up 2>/dev/null || true")

    net.start()

    # TUYỆT CHIÊU 2: TẮT IPV6 SAU KHI CÓ INTERFACE (giảm nhiễu control plane / ONOS)
    print("*** Vô hiệu hóa IPv6 để bảo vệ Control Plane...")
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    print("Mininet network started")
    
    print("*** Đảm bảo các Switch thuần Lớp 2 (Không có IP)...")
    for s in net.switches:
        s.cmd(f"ifconfig {s.name} 0.0.0.0 2>/dev/null") 
        
    time.sleep(15) # Thời gian vàng để ONOS vẽ Link SCCs: 1

    '''print("*** Setting IP cho Docker hosts...")
    for docker_name, docker_ip in (('web1', '10.0.0.10'), ('db1', '10.0.0.20')):
        h = net.get(docker_name)
        for intf in h.intfList():
            if intf.name == 'lo': continue
            h.setIP(f"{docker_ip}/24", intf=intf.name)
            h.cmd(f"ip link set {intf.name} up >/dev/null 2>&1 || true")'''
    return net
# -------------------------------------------------
# NETCFG
# -------------------------------------------------

def push_netcfg():

    print("Deploying netcfg...")

    result = os.system(
        "curl --user onos:rocks "
        "-H 'Content-Type: application/json' "
        "-X POST "
        "http://localhost:8181/onos/v1/network/configuration "
        "-d @onos/netcfg.json "
        "-w '\\nStatus: %{http_code}\\n'"
    )
    
    if result == 0:
        print("✓ netcfg deployed successfully")
    else:
        print("✗ netcfg deployment failed, retrying...")
        time.sleep(2)
        os.system(
            "curl -v --user onos:rocks "
            "-H 'Content-Type: application/json' "
            "-X POST "
            "http://localhost:8181/onos/v1/network/configuration "
            "-d @onos/netcfg.json"
        )


# -------------------------------------------------
# SERVICES
# -------------------------------------------------

def start_services(net):
    print("Starting services (Logs redirected to /tmp/...)")
    net.get("proxy1").cmd("nginx -g 'daemon off;' > /tmp/nginx_proxy.log 2>&1 &")
    net.get("h70").cmd("python3 services/webserver.py > /tmp/web.log 2>&1 &")
    net.get("h71").cmd("python3 services/dns.py > /tmp/dns.log 2>&1 &")
    net.get("h72").cmd("python3 services/api.py > /tmp/api.log 2>&1 &")
    net.get("h80").cmd("python3 ids/gnn_ids.py > /tmp/gnn_ids.log 2>&1 &")
    net.get("h81").cmd("python3 services/honeypot.py > /tmp/honeypot.log 2>&1 &")
    net.get("h82").cmd("sh -c 'pip install -q scapy > /tmp/pip_h82.log 2>&1 && python3 monitor/http_mirror_capture.py > /tmp/capture.log 2>&1 &'")

    print("*** Khởi động Django Web Server trên web1...")
    web1 = net.get("web1")
    # Chạy Django development server - mặc định đã có threading
    web1.cmd("sh -c 'cd /app && python manage.py runserver 0.0.0.0:8000 > /tmp/django.log 2>&1 &'")
# -------------------------------------------------
# NORMAL TRAFFIC
# -------------------------------------------------

def start_normal_traffic(net):

    print("Generating normal traffic")

    for i in range(60, 66):

        client = net.get(f"h{i}")

        client.cmd("python3 traffic/normal.py http://10.0.0.11:8000 &")


# -------------------------------------------------
# MAIN
# -------------------------------------------------

def main():
    # Cho phép định tuyến giữa các subnet trên máy Host
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")
    
    clean_mininet()

    if wait_for_onos():
        pass

    enable_apps()
    #ĐỂ SWITCH KHÔNG BỊ TỪ CHỐI KẾT NỐI LÚC ĐẦU
    print("[SYSTEM] Đang chờ ONOS nạp giao thức OpenFlow (10s)...")
    time.sleep(10)
    # Khởi tạo mạng
    net = start_network()
    time.sleep(5)

    wait_devices()
    time.sleep(3)

    # # Đẩy cấu hình tọa độ và tên
    # push_netcfg()

    # Chờ ONOS converge routes và flow ổn định (giảm link flapping)
    print("*** Chờ ONOS converge routes (25 giây)...")
    time.sleep(25)
        
    print("*** Tự động cấu hình Định tuyến Trực tiếp L2 (L2 Flat Routing)...")
    docker_ips = {"web1": "10.0.0.11", "proxy1": "10.0.0.10", "db1": "10.0.0.20"}
    subnets = ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/24']

    for host in net.hosts:
        ip = host.IP()
        if not ip and host.name in docker_ips: 
            ip = docker_ips[host.name]
        if not ip: 
            continue
        
        host.cmd('route del default 2>/dev/null')
        iface = host.defaultIntf().name
        
        # Bơm Route trực tiếp để các Host gọi thẳng nhau qua L2
        for subnet in subnets:
            host.cmd(f'ip route add {subnet} dev {iface} 2>/dev/null')

        if isinstance(host, Docker):
            host.cmd('sysctl -w net.ipv4.ip_forward=1')

    print("*** Cấu hình L2 Flat Routing hoàn tất! Mạng đã thông suốt.")
    print("*** Cấu hình định tuyến và Keep-alive hoàn tất!")
    
    # Chờ ONOS converge - flow/LLDP ổn định trước khi bật traffic
    print("*** Waiting for ONOS initial routing (20s)... - ổn định link")
    time.sleep(20) # Đủ lâu để LLDP discovery ổn định, giảm nét đứt đỏ
    
    
    
    print("*** Host discovery (Optimized) - Bắt đầu nhận diện mạng tuần tự...")

    hosts = net.hosts

    # Phase 1: Nhận diện mạng siêu tốc (Lightweight & Parallel)
    print("*** Phase 1: Gửi tín hiệu để ONOS học MAC (Ping & UDP)...")
    representatives = {'10.0.0': '10.0.0.100', '10.0.1': '10.0.1.10', '10.0.2': '10.0.2.60'}
    
    for h in hosts:
        ip = h.IP()
        if not ip:
            print(f"ip {ip} không tồn tại, đã bỏ qua")
            continue
            
        # Phân loại: Docker slim không có lệnh ping, phải dùng Python UDP
        if h.name in ["web1", "proxy1", "db1"]:
            h.cmd("python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b\"\", (\"10.0.0.100\", 80))' &")
        
        # Các host Mininet bình thường thì dùng ping
        else:
            subnet = '.'.join(ip.split('.')[:3])
            rep = representatives.get(subnet)
            if rep and ip != rep: # Tránh tự ping chính mình
                h.cmd(f"ping -c 1 -W 1 {rep} >/dev/null 2>&1 &") # Bắn lệnh xuống nền (&) và timeout 1s để CPU xử lý song song siêu tốc
    
    print("*** Đang chờ ONOS cập nhật luồng cơ bản (10s)...")
    time.sleep(10)

    # Phase 2: Cross-subnet discovery
    print("*** Phase 2: Cross-subnet discovery - Kích hoạt liên thông...")
    cross_targets = [
        '10.0.0.100', '10.0.0.20', '10.0.0.10', '10.0.0.11', '10.0.0.101', '10.0.0.200',
        '10.0.1.1', '10.0.1.10', '10.0.1.20',
        '10.0.2.60', '10.0.2.61', '10.0.2.65'
    ]
    
    batch_size = 6
    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i+batch_size]
        for h in batch:
            ip = h.IP()
            if not ip: continue
            ip_clean = ip.split('/')[0]
            my_subnet = '.'.join(ip_clean.split('.')[:3])
            
            for t in cross_targets:
                t_subnet = '.'.join(t.split('.')[:3])
                if t_subnet != my_subnet:
                    if h.name in ("web1", "proxy1"):
                        # web1 KHÔNG có lệnh ping, dùng Python nhồi gói tin UDP
                        h.cmd(f"python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b\"ping\", (\"{t}\", 80))' 2>/dev/null &")
                    else:
                        h.cmd(f"ping -c 1 -W 1 {t} 2>/dev/null &")
        time.sleep(1.5)
        
    print("Hoàn thành phase 2, đợi 25 giây trong lúc cập nhật topo")
    time.sleep(25)

    # Phase 3: Round 2
    print("*** Phase 3: Cross-subnet round 2 (Bidirectional flows)...")
    for h in hosts:
        ip = h.IP()
        if not ip: continue
        ip_clean = ip.split('/')[0]
        my_subnet = '.'.join(ip_clean.split('.')[:3])
        
        for t in cross_targets[:3]: 
            t_subnet = '.'.join(t.split('.')[:3])
            if t_subnet != my_subnet:
                if h.name in ("web1", "proxy1"):
                    h.cmd(f"python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b\"ping\", (\"{t}\", 80))' 2>/dev/null &")
                else:
                    h.cmd(f"ping -c 1 -W 1 {t} 2>/dev/null")
                
    print("*** Hoàn tất nhận diện mạng. Đang chờ hệ thống ổn định hoàn toàn (10s)...")
    time.sleep(10)
    wait_hosts(timeout=10)
    print("*** Đang chờ hệ thống ổn định hoàn toàn để deploy netcfg (15s)...")
    time.sleep(15)
    # Đẩy cấu hình tọa độ và tên
    push_netcfg()
    time.sleep(5)
    configure_local_mirroring(net)

    # Khởi chạy các dịch vụ web, dns, ids...
    start_services(net)
    time.sleep(5)

    # Tạo lưu lượng nền (Normal Traffic)
    start_normal_traffic(net)
    
    # Initialize database (redirect output to file)
    print("*** Initializing Database...")
    try:
        with open('/tmp/init_db.log', 'w') as log_file:
            subprocess.Popen(
                ["python3", "dataset/init_db.py"],
                stdout=log_file,
                stderr=log_file
            )
    except Exception as e:
        print(f"[!] Error initializing database: {e}")
    
    # Chạy script highlight (nếu có) - redirect output
    if os.path.exists("onos/highlight_bot.py"):
        try:
            with open('/tmp/highlight_bot.log', 'w') as log_file:
                subprocess.Popen(
                    ["python3", "onos/highlight_bot.py"],
                    stdout=log_file,
                    stderr=log_file
                )
        except Exception as e:
            print(f"[!] Error running highlight_bot: {e}")

    # ========== DEBUG INFO ==========
    print("\n" + "="*60)
    print("[HỆ THỐNG] TẤT CẢ DỊCH VỤ ĐÃ KHỞI ĐỘNG")
    print("="*60)
    
    # Lấy thông tin từ ONOS
    try:
        r = requests.get(f"{ONOS_BASE}/devices", auth=AUTH, timeout=5)
        if r.status_code == 200:
            devices = r.json()['devices']
            num_switches = len(devices)
            print(f"[ONOS] Số Switch: {num_switches}/6 ✓" if num_switches == 6 else f"[ONOS] Số Switch: {num_switches}/6")
    except:
        pass
    
    try:
        r = requests.get(f"{ONOS_BASE}/hosts", auth=AUTH, timeout=5)
        if r.status_code == 200:
            hosts = r.json()['hosts']
            num_hosts = len(hosts)
            print(f"[ONOS] Số Host: {num_hosts}/35")
    except:
        pass
    print("="*60 + "\n")

    print("\n[HỆ THỐNG] Đang tự động cài đặt Database và khởi động Web Server...")
    web1 = net.get('web1')
    print("[HỆ THỐNG] Đang nạp dữ liệu vào PostgreSQL (xem chi tiết tại /tmp/db_setup.log)...")
    web1.cmd('python /app/setup_db.py > /tmp/db_setup.log 2>&1')
    
    time.sleep(2)
    print("[HỆ THỐNG] Sẵn sàng! HTTPS proxy tại: https://10.0.0.10")
    _ensure_proxy1_https_localhost_proxy()
    _ensure_web1_localhost_proxy() # Start Web1 tunnel for Dashboard
    print(f"[HỆ THỐNG] HTTPS local cho máy thật: https://127.0.0.1:{PROXY1_HOST_HTTPS_PORT}")
    print(f"[HỆ THỐNG] Web1 local (tunnel) cho Dashboard: http://127.0.0.1:{WEB1_HOST_PORT}")
    print("[HỆ THỐNG] Dashboard host (out-of-band): http://127.0.0.1:8050")
    print("[HỆ THỐNG] Đã tắt auto-open Edge để tránh cửa sổ treo/không click được.")
    print("[HỆ THỐNG] Mở web từ host bất kỳ trong topo bằng lệnh:")
    print("  containernet> h60 python3 tools/open_web_from_host.py")
    print("  containernet> h61 python3 tools/open_web_from_host.py --path /accounts/login/")

    CLI(net)
    net.stop()




    '''url_topo = "http://10.0.0.10:8000"
    url_local = f"http://127.0.0.1:{WEB1_HOST_PORT}"

    # Containernet: web1 gắn OVS nên docker -p 8000:8000 thường không tới host — bật proxy qua docker exec.
    if not _django_on_localhost_ok():
        print(
            "[HỆ THỐNG] 127.0.0.1:8000 chưa có (bình thường với web1 trên OVS) — "
            f"bật proxy → container {DOCKER_WEB1_CNAME}…"
        )
        _ensure_web1_localhost_proxy()
        for _ in range(30):
            time.sleep(0.5)
            if _django_on_localhost_ok():
                break

    if _django_on_localhost_ok():
        if _spawn_browser_on_desktop(url_local):
            print(
                f"[HỆ THỐNG] Đã mở {url_local} (cùng Django với {url_topo} trong topo SDN)."
            )
        else:
            print(f"[!] Không khởi chạy được trình duyệt. Mở tay: {url_local} hoặc {url_topo}")
    else:
        display = os.environ.get("DISPLAY", ":1")
        browser = _pick_gui_browser()
        if not browser:
            print(
                f"[!] Không mở được qua localhost/proxy và không có trình duyệt. Mở tay: {url_topo}"
            )
        else:
            exports = [f"export DISPLAY={shlex.quote(display)}"]
            xauth = os.environ.get("XAUTHORITY")
            if xauth:
                exports.append(f"export XAUTHORITY={shlex.quote(xauth)}")
            argv = _build_browser_argv(browser, url_topo, isolated_profile=True)
            inner = " ".join(shlex.quote(x) for x in argv)
            h60.cmd(" && ".join(exports) + f" && {inner} > /dev/null 2>&1 &")
            print(
                f"[HỆ THỐNG] Proxy/docker thất bại — đã gọi {os.path.basename(browser)} "
                f"trên netns h60 tới {url_topo} (DISPLAY={display})."
            )
    CLI(net)
    net.stop()'''

if __name__ == "__main__":
    setLogLevel("info")
    main()
