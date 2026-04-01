#!/usr/bin/python3
from requests.auth import HTTPBasicAuth

import os
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
from mininet.link import TCLink


class StableOVSSwitch(OVSSwitch):
    """OVS với reconnectms cao hơn để giảm link flapping khi mất kết nối tạm thời với ONOS."""
    def __init__(self, name, **kwargs):
        kwargs.setdefault('reconnectms', 5000)  # 5s thay vì mặc định ~1s
        OVSSwitch.__init__(self, name, **kwargs)

ONOS_BASE = "http://localhost:8181/onos/v1"
AUTH = ("onos", "rocks")

EXPECTED_SWITCHES = 6
EXPECTED_HOSTS = 33

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
# START NETWORK
# -------------------------------------------------

def start_network():
    topo = ResearchTopo()
    # XÓA CONTAINER CŨ TRƯỚC KHI CHẠY
    print("*** Dọn dẹp các Docker container cũ...")
    subprocess.call(["docker", "rm", "-f", "web1", "db1"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    # Khởi tạo mạng bằng Containernet (thay vì Mininet)
    # Lưu ý: Bạn cần import Containernet ở đầu file system.py
    net = Containernet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="172.17.0.2", port=6653),
        switch=StableOVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )

    print("*** Đang thêm các máy chủ Docker vào hệ thống...")
    
    # 1. Thêm Web Server Django
    web1 = net.addDocker('web1', 
                         ip='10.0.0.10', 
                         dimage="python:3.9-slim", 
                         mem_limit="256m", cpu_quota=25000, # Giới hạn 256MB RAM và 25% CPU
                         volumes=["/home/tgf/Documents/DoAn_SDN/services/my_web_app:/app"])
    # 2. Thêm Database PostgreSQL
    db1 = net.addDocker('db1', 
                    ip='10.0.0.20', 
                    dimage="postgres:15-alpine", 
                    mem_limit="512m", cpu_quota=50000, # Giới hạn 512MB RAM và 50% CPU
                    environment={
                        "POSTGRES_PASSWORD": "root",
                        "POSTGRES_USER": "postgres",
                        "POSTGRES_DB": "postgres",
                        "POSTGRES_HOST_AUTH_METHOD": "trust" 
                    },
                    dcmd="/usr/local/bin/docker-entrypoint.sh postgres")
    # 3. Kết nối chúng vào Switch Datacenter (s5)
    s5 = net.get('s5')
    net.addLink(web1, s5)
    net.addLink(db1, s5)

    # ========== DỌN RÁC INTERFACE CŨ TRƯỚC KHỞI ĐỘNG ==========
    print("*** Dọn dẹp interface cũ từ các lần chạy trước...")
    os.system("sudo ip link show | grep -E '^[0-9]+:' | grep -E '(s[0-9]|h[0-9]|web|db)' | awk '{print $2}' | sed 's/:$//' | while read iface; do sudo ip link del $iface 2>/dev/null; done")
    os.system("sudo ovs-vsctl --if-exists del-br s1 -- --if-exists del-br s2 -- --if-exists del-br s3 -- --if-exists del-br s4 -- --if-exists del-br s5 -- --if-exists del-br s6 2>/dev/null")
    time.sleep(2)

    net.start()
    print("Mininet network started")
    time.sleep(30)
    print("*** Setting IP cho Docker hosts (Mininet model + container)...")
    # Lý do: pingall dùng dest.IP() từ Mininet model (Intf.ip),
    # nếu chỉ ifconfig trong container thì Intf.ip có thể vẫn là None => ping tới "None".
    for docker_name, docker_ip in (('web1', '10.0.0.10'), ('db1', '10.0.0.20')):
        h = net.get(docker_name)
        for intf in h.intfList():
            if intf.name == 'lo':
                continue
            # setIP sẽ cập nhật Intf.ip trong Mininet model
            h.setIP(f"{docker_ip}/24", intf=intf.name)
            h.cmd(f"ip link set {intf.name} up >/dev/null 2>&1 || true")

    # --- PHẦN BỔ SUNG QUAN TRỌNG ---
    print("*** Cấu hình OpenFlow 1.3 và Gateway cho Switch...")
    for s in net.switches:
        # Ép dùng OpenFlow 1.3 cho ONOS
        s.cmd(f"ovs-vsctl set bridge {s.name} protocols=OpenFlow13")
        
    # Gán IP Gateway cho các Switch để các Subnet có "cửa ra"
    # IMPORTANT: Must match the .1 addresses that hosts use as default gateway
    net.get('s5').cmd('ifconfig s5 10.0.0.1 netmask 255.255.255.0 up') # Gateway cho Server (h70-h82)
    net.get('s6').cmd('ifconfig s6 10.0.0.1 netmask 255.255.255.0 up') # Gateway cho WebServer h70 (same subnet)
    net.get('s3').cmd('ifconfig s3 10.0.2.1 netmask 255.255.255.0 up') # Gateway cho Client
    net.get('s4').cmd('ifconfig s4 10.0.1.1 netmask 255.255.255.0 up') # Gateway cho Botnet

    # Thiết lập Route mặc định cho Docker (vì addDocker không tự gán Gateway)
    print("*** Thiết lập Route cho Docker hosts...")
    web1.cmd('route add default gw 10.0.0.1')
    db1.cmd('route add default gw 10.0.0.1')
    
    # Cho phép Forwarding bên trong Docker
    web1.cmd('sysctl -w net.ipv4.ip_forward=1')
    db1.cmd('sysctl -w net.ipv4.ip_forward=1')

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

#def start_services(net):
    #print("Starting services")
    #net.get("h70").cmd("python3 services/webserver.py &")
    #net.get("h71").cmd("python3 services/dns.py &")
    #net.get("h72").cmd("python3 services/api.py &")
    #net.get("h80").cmd("python3 ids/gnn_ids.py &")
    #net.get("h81").cmd("python3 services/honeypot.py &")
    #net.get("h82").cmd("python3 monitor/capture.py &")
def start_services(net):
    print("Starting services (Logs redirected to /tmp/...)")
    net.get("h70").cmd("python3 services/webserver.py > /tmp/web.log 2>&1 &")
    net.get("h71").cmd("python3 services/dns.py > /tmp/dns.log 2>&1 &")
    net.get("h72").cmd("python3 services/api.py > /tmp/api.log 2>&1 &")
    net.get("h80").cmd("python3 ids/gnn_ids.py > /tmp/gnn_ids.log 2>&1 &")
    net.get("h81").cmd("python3 services/honeypot.py > /tmp/honeypot.log 2>&1 &")
    net.get("h82").cmd("python3 monitor/capture.py > /tmp/capture.log 2>&1 &")

# -------------------------------------------------
# NORMAL TRAFFIC
# -------------------------------------------------

def start_normal_traffic(net):

    print("Generating normal traffic")

    for i in range(60, 66):

        client = net.get(f"h{i}")

        client.cmd("python3 traffic/normal.py 10.0.0.100 &")


# -------------------------------------------------
# MAIN
# -------------------------------------------------

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
    print("*** Chờ ONOS converge routes (45 giây)...")
    time.sleep(45)
    
    print("*** Đang tự động cấu hình định tuyến và giữ kết nối cho Hosts...")
    
    
    # Manual IP dict for Docker hosts (they don't call host.IP() properly)
    docker_ips = {
        'web1': '10.0.0.10',
        'db1': '10.0.0.20'
    }

    for idx, host in enumerate(net.hosts):
        # Try to get IP from host.IP() first, fallback to docker_ips dict
        ip = host.IP()
        if not ip and host.name in docker_ips:
            ip = docker_ips[host.name]
        
        if not ip:
            print(f"[CẢNH BÁO] Host {host.name} chưa có IP, đang bỏ qua...")
            continue
        
        # Xác định Gateway có interface thực tế trên switch
        if ip.startswith('10.0.1.'):   # Subnet Botnet
            gw = '10.0.1.1'
        elif ip.startswith('10.0.2.'): # Subnet Client
            gw = '10.0.2.1'
        elif ip.startswith('10.0.0.'): # Subnet Dịch vụ
            gw = '10.0.0.1'
        else:
            gw = None

        if gw:
            # 1. Clear old routes and add route to correct gateway
            host.cmd('route del default 2>/dev/null')
            host.cmd(f'route add default gw {gw}')
            
            # 2. Keep-alive: ping gateway ONLY, interval 30s (giảm tải để ổn định link)
            # Stagger: mỗi host delay khác nhau (idx*1.5s) để tránh ping storm đồng thời
            stagger = int(idx * 1.5) % 25  # Spread over 0-25 seconds
            host.cmd(f"(sleep {stagger} && while true; do ping -c 1 -W 1 {gw} 2>/dev/null; sleep 60; done) &")

        # Kích hoạt IP Forwarding nếu là Docker host
        if isinstance(host, Docker):
            host.cmd('sysctl -w net.ipv4.ip_forward=1')

    print("*** Cấu hình định tuyến và Keep-alive hoàn tất!")
    
    # Chờ ONOS converge - flow/LLDP ổn định trước khi bật traffic
    print("*** Waiting for ONOS initial routing (20s)... - ổn định link")
    time.sleep(20) # Đủ lâu để LLDP discovery ổn định, giảm nét đứt đỏ
    
    
    
    print("*** Host discovery (Optimized) - Bắt đầu nhận diện mạng tuần tự...")

    hosts = net.hosts
    gateways = {'10.0.0': '10.0.0.1', '10.0.1': '10.0.1.1', '10.0.2': '10.0.2.1'}
    
    # Phase 1: Nhận diện Gateway (Lightweight & Synchronous)
    print("*** Phase 1: Lightweight Host Discovery - Gửi Ping đến Gateway...")
    for h in hosts:
        ip = h.IP()
        if ip:
            subnet = '.'.join(ip.split('.')[:3])
            gw = gateways.get(subnet)
            if gw:
                # QUAN TRỌNG: Không dùng '&' ở cuối. 
                # Chạy tuần tự để CPU không phải gánh hàng chục tiến trình bash cùng lúc
                h.cmd(f"ping -c 1 -W 1 {gw} 2>/dev/null") 
    
    # Nghỉ một nhịp ngắn để ONOS xử lý các luồng (flows) cơ bản
    print("*** Đang chờ ONOS cài đặt Flow cơ bản (5s)...")
    time.sleep(10)

    # Phase 2: Cross-subnet discovery (Nhận diện liên mạng)
    print("*** Phase 2: Cross-subnet discovery - Kích hoạt liên thông tuần tự...")
    cross_targets = [
        '10.0.0.100', '10.0.0.20', '10.0.0.10', '10.0.0.101', '10.0.0.200',
        '10.0.1.1', '10.0.1.10', '10.0.1.20',
        '10.0.2.60', '10.0.2.61', '10.0.2.65'
    ]
    
    # Duyệt qua từng host, gửi ping tuần tự và có nhịp nghỉ
    for h in hosts:
        ip = h.IP()
        if not ip:
            continue
        ip_clean = ip.split('/')[0]
        my_subnet = '.'.join(ip_clean.split('.')[:3])
        
        for t in cross_targets:
            t_subnet = '.'.join(t.split('.')[:3])
            if t_subnet != my_subnet:
                # Chỉ gửi 1 gói tin (-c 1), chờ tối đa 3s (-W 3), chạy tuần tự
                h.cmd(f"ping -c 1 -W 3 {t} 2>/dev/null")
        
        # Nhịp nghỉ 0.2s sau mỗi host để Controller (ONOS) kịp "thở" và cập nhật Topology
        time.sleep(0.2)
    time.sleep(25)

    
    # Phase 3: Round 2 - Đảm bảo flow hai chiều (Rút gọn)
    print("*** Phase 3: Cross-subnet round 2 (Bidirectional flows)...")
    for h in hosts:
        ip = h.IP()
        if not ip:
            continue
        ip_clean = ip.split('/')[0]
        my_subnet = '.'.join(ip_clean.split('.')[:3])
        
        # Chỉ lấy 3 target đầu tiên làm đại diện để thiết lập chiều về, tiết kiệm tài nguyên
        for t in cross_targets[:3]: 
            t_subnet = '.'.join(t.split('.')[:3])
            if t_subnet != my_subnet:
                h.cmd(f"ping -c 1 -W 1 {t} 2>/dev/null")
                
    print("*** Hoàn tất nhận diện mạng. Đang chờ hệ thống ổn định hoàn toàn (10s)...")
    time.sleep(10)
    wait_hosts(timeout=10)

    # Đẩy cấu hình tọa độ và tên
    push_netcfg()
    time.sleep(5)

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
    print("[HỆ THỐNG] ✅ TẤT CẢ DỊCH VỤ ĐÃ KHỞI ĐỘNG")
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
            print(f"[ONOS] Số Host: {num_hosts}/33")
    except:
        pass
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()
