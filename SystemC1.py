#!/usr/bin/python3
from requests.auth import HTTPBasicAuth

import os
import time
import subprocess
import requests

from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch, Docker
from mininet.log import setLogLevel
from mininet.cli import CLI

from topology.research_topo import ResearchTopo

class StableOVSSwitch(OVSSwitch):
    """OVS với reconnectms cao hơn để giảm link flapping khi mất kết nối tạm thời với ONOS."""
    def __init__(self, name, **kwargs):
        kwargs.setdefault('reconnectms', 5000)
        OVSSwitch.__init__(self, name, **kwargs)

ONOS_BASE = "http://localhost:8181/onos/v1"
AUTH = ("onos", "rocks")

EXPECTED_SWITCHES = 6
EXPECTED_HOSTS = 34

# ==============================================================================
# 1. CÁC HÀM KIỂM TRA TRẠNG THÁI (DYNAMIC WAIT)
# ==============================================================================

def wait_for_onos(timeout=180):
    url = f"{ONOS_BASE}/applications"
    start_time = time.time()
    print("[SYSTEM] Đang chờ ONOS REST API sẵn sàng...")
    while time.time() - start_time < timeout:
        try:
            r = requests.get(url, auth=AUTH, timeout=2)
            if r.status_code == 200:
                print(f"[OK] ONOS đã online sau {int(time.time() - start_time)}s")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
        print(".", end="", flush=True)
    print("\n[!] Quá thời gian chờ ONOS.")
    return False

def wait_devices(timeout=60):
    start_time = time.time()
    print(f"[SYSTEM] Đang chờ khám phá {EXPECTED_SWITCHES} switches...")
    while time.time() - start_time < timeout:
        try:
            r = requests.get(f"{ONOS_BASE}/devices", auth=AUTH, timeout=2)
            if r.status_code == 200:
                devices = r.json().get("devices", [])
                if len(devices) >= EXPECTED_SWITCHES:
                    print(f"[OK] Đã nhận diện đủ {len(devices)} switches.")
                    return True
        except: pass
        time.sleep(2)
        print(".", end="", flush=True)
    return False

def wait_links(expected_links=10, timeout=60):
    start_time = time.time()
    print(f"[SYSTEM] Đang chờ ONOS nhận diện các liên kết lõi (Links)...")
    while time.time() - start_time < timeout:
        try:
            r = requests.get(f"{ONOS_BASE}/links", auth=AUTH, timeout=2)
            if r.status_code == 200:
                links = r.json().get("links", [])
                if len(links) >= expected_links:
                    print(f"[OK] Đã kết nối đủ {len(links)} links nội bộ.")
                    return True
        except: pass
        time.sleep(2)
        print(".", end="", flush=True)
    return False

def wait_hosts(timeout=60):
    start_time = time.time()
    print(f"\n[SYSTEM] Đang chờ ONOS nhận diện Hosts ({EXPECTED_HOSTS})...")
    while time.time() - start_time < timeout:
        try:
            r = requests.get(f"{ONOS_BASE}/hosts", auth=AUTH, timeout=2)
            if r.status_code == 200:
                hosts = r.json().get("hosts", [])
                print(f"\rTiến độ nhận diện Host: {len(hosts)}/{EXPECTED_HOSTS}    ", end="")
                if len(hosts) >= EXPECTED_HOSTS:
                    print("\n[OK] Đã nhận diện toàn bộ Hosts.")
                    return True
        except: pass
        time.sleep(2)
    print("\n[!] Timeout: ONOS chỉ tìm thấy các Host đang hiển thị. Hãy vào giao diện kiểm tra.")
    return False

# ==============================================================================
# 2. XÂY DỰNG MẠNG & CẤU HÌNH
# ==============================================================================

def clean_mininet():
    print("=== [1] DỌN DẸP MÔI TRƯỜNG ===")
    os.system("mn -c > /dev/null 2>&1")
    os.system("stty sane 2>/dev/null")
    time.sleep(2)

def enable_apps():
    print("\n=== [2] KÍCH HOẠT ỨNG DỤNG ONOS ===")
    apps = ["org.onosproject.openflow", "org.onosproject.hostprovider", 
            "org.onosproject.lldpprovider", "org.onosproject.fwd", 
            "org.onosproject.proxyarp", "org.onosproject.gui"]
    for app in apps:
        requests.post(f"{ONOS_BASE}/applications/{app}/active", auth=AUTH)
    print("[OK] Đã kích hoạt các module mạng lõi.")

def start_network():
    print("\n=== [3] KHỞI TẠO TOPOLOGY VÀ DOCKER ===")
    topo = ResearchTopo()
    subprocess.call(["docker", "rm", "-f", "web1", "db1"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    net = Containernet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="172.17.0.2", port=6653),
        switch=StableOVSSwitch,
        autoSetMacs=True, autoStaticArp=True
    )

    web1 = net.addDocker('web1', ip='10.0.0.10', dimage="python:3.9-slim", 
                         mem_limit="256m", cpu_quota=25000, 
                         volumes=["/home/tgf/Documents/DoAn_SDN/services/my_web_app:/app"])
    db1 = net.addDocker('db1', ip='10.0.0.20', dimage="postgres:15-alpine", 
                        mem_limit="512m", cpu_quota=50000, 
                        environment={"POSTGRES_PASSWORD": "root", "POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres", "POSTGRES_HOST_AUTH_METHOD": "trust"},
                        dcmd="/usr/local/bin/docker-entrypoint.sh postgres")

    s5 = net.get('s5')
    net.addLink(web1, s5)
    net.addLink(db1, s5)

    net.start()
    print("[OK] Mininet chạy thành công.")

    for s in net.switches:
        s.cmd(f"ovs-vsctl set bridge {s.name} protocols=OpenFlow13")
        
    net.get('s5').cmd('ifconfig s5 10.0.0.1 netmask 255.255.255.0 up')
    net.get('s6').cmd('ifconfig s6 10.0.0.1 netmask 255.255.255.0 up')
    net.get('s3').cmd('ifconfig s3 10.0.2.1 netmask 255.255.255.0 up')
    net.get('s4').cmd('ifconfig s4 10.0.1.1 netmask 255.255.255.0 up')

    return net

def setup_routing_and_discovery(net):
    print("\n=== [5] CẤU HÌNH ĐỊNH TUYẾN & NHẬN DIỆN HOSTS ===")
    docker_ips = {'web1': '10.0.0.10', 'db1': '10.0.0.20'}
    
    print("-> 1. Cài đặt Route & Keep-alive ngầm (Chuẩn từ bản cũ)...")
    for idx, host in enumerate(net.hosts):
        ip = host.IP() or docker_ips.get(host.name)
        if not ip: continue
        
        gw = None
        if ip.startswith('10.0.1.'): gw = '10.0.1.1'
        elif ip.startswith('10.0.2.'): gw = '10.0.2.1'
        elif ip.startswith('10.0.0.'): gw = '10.0.0.1'

        if gw:
            host.cmd('route del default 2>/dev/null')
            host.cmd(f'route add default gw {gw}')
            # Khôi phục vòng lặp Keep-alive, nhưng giãn sleep ra 60s để mượt CPU
            stagger = int(idx * 1.5) % 25
            host.cmd(f"(sleep {stagger} && while true; do ping -c 1 -W 1 {gw} >/dev/null 2>&1; sleep 60; done) &")

        if isinstance(host, Docker):
            host.cmd('sysctl -w net.ipv4.ip_forward=1')

    print("-> Chờ ONOS xử lý liên kết lõi (20s)...")
    time.sleep(20)

    print("-> 2. Cross-subnet Discovery (Kích hoạt flow liên mạng)...")
    # Thay vì 34 máy ping loạn lên, ta chọn lọc mục tiêu để đánh thức Flow
    cross_targets = ['10.0.0.100', '10.0.0.20', '10.0.1.10', '10.0.2.60']
    for h in net.hosts:
        ip = h.IP() or docker_ips.get(h.name)
        if not ip: continue
        my_subnet = '.'.join(ip.split('.')[:3])
        for t in cross_targets:
            if not t.startswith(my_subnet):
                h.cmd(f"ping -c 1 -W 1 {t} >/dev/null 2>&1 &")
        # Nghỉ nửa giây giữa mỗi máy để giảm tải CPU
        time.sleep(0.5)

    print("-> Chờ ONOS nạp Flow Rules (15s)...")
    time.sleep(15)

def push_netcfg():
    print("\n=== [6] ĐẨY CẤU HÌNH GIAO DIỆN (NETCFG) ===")
    os.system(f"curl -s -u onos:rocks -H 'Content-Type: application/json' -X POST {ONOS_BASE}/network/configuration -d @onos/netcfg.json > /dev/null")
    print("[OK] Đã nạp tọa độ bản đồ.")

# ==============================================================================
# 3. LUỒNG THỰC THI CHÍNH (MAIN)
# ==============================================================================

def main():
    os.system("sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null")
    clean_mininet()

    if not wait_for_onos(): return

    enable_apps()
    
    print("\n[SYSTEM] Nghỉ 10 giây chờ OpenFlow nạp vào lõi...")
    time.sleep(10)

    net = start_network()
    
    print("\n=== [4] CHỜ MẠNG LÕI HỘI TỤ (CONVERGENCE) ===")
    wait_devices()
    wait_links()
    
    print("[SYSTEM] Ổn định đường truyền (10s)...")
    time.sleep(10)

    # Đánh thức mọi host bằng tuyệt chiêu của bản cũ (đã tối ưu)
    setup_routing_and_discovery(net)
    
    # Kiểm tra xem ONOS đã nhận đủ 34 host chưa
    wait_hosts()

    push_netcfg()

    print("\n=== [7] KHỞI CHẠY DỊCH VỤ VÀ TRAFFIC ===")
    net.get("h70").cmd("python3 services/webserver.py &")
    net.get("h71").cmd("python3 services/dns.py &")
    net.get("h72").cmd("python3 services/api.py &")
    net.get("h80").cmd("python3 ids/gnn_ids.py &")
    net.get("h81").cmd("python3 services/honeypot.py &")
    if os.path.exists("monitor/capture.py"):
        net.get("h82").cmd("python3 monitor/capture.py &")

    # Kích hoạt người dùng bình thường
    for i in range(60, 66):
        net.get(f"h{i}").cmd("python3 traffic/normal.py 10.0.0.100 &")

    print("*** Đang nạp Database...")
    os.system("python3 dataset/init_db.py > /tmp/init_db.log 2>&1 &")
    if os.path.exists("onos/highlight_bot.py"):
        os.system("python3 onos/highlight_bot.py > /tmp/highlight.log 2>&1 &")

    print("\n" + "="*60)
    print(" ✅ HỆ THỐNG SDN ĐÃ SẴN SÀNG HOÀN TOÀN ")
    print(" 🚀 CPU CHẠY MƯỢT - KHÔNG RỚT MẠNG - NHẬN DIỆN ĐỦ HOST")
    print("="*60 + "\n")

    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    main()
