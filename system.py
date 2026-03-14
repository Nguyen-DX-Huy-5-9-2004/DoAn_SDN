#!/usr/bin/python3

import os
import time
import subprocess
import requests

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel
from mininet.cli import CLI

from topology.research_topo import ResearchTopo


ONOS_BASE = "http://localhost:8181/onos/v1"
AUTH = ("onos", "rocks")

EXPECTED_SWITCHES = 5
EXPECTED_HOSTS = 62


# -------------------------------------------------
# CLEAN
# -------------------------------------------------

def clean_mininet():

    print("[SYSTEM] Cleaning old Mininet environment...")

    os.system("mn -c > /dev/null 2>&1")

    time.sleep(2)

    print("[SYSTEM] Environment ready")


# -------------------------------------------------
# WAIT ONOS
# -------------------------------------------------

def wait_onos_ready():

    print("Waiting ONOS REST API")

    while True:

        try:

            r = requests.get(
                f"{ONOS_BASE}/devices",
                auth=AUTH,
                timeout=3
            )

            if r.status_code == 200:
                print("ONOS API ready")
                return

        except:
            pass

        time.sleep(3)


# -------------------------------------------------
# WAIT DEVICES
# -------------------------------------------------

def wait_devices():

    print("Waiting switches discovery")

    while True:

        r = requests.get(
            f"{ONOS_BASE}/devices",
            auth=AUTH
        )

        devices = r.json()["devices"]

        if len(devices) >= EXPECTED_SWITCHES:

            print("All switches discovered")

            return

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
        "org.onosproject.proxyarp"
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

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name,
            ip="127.0.0.2",
            port=6653
        ),
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )

    net.start()

    print("Mininet network started")

    # FORCE OpenFlow13
    for s in net.switches:
        s.cmd(f"ovs-vsctl set bridge {s.name} protocols=OpenFlow13")

    return net

def start_network():

    topo = ResearchTopo()

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name,
            ip="127.0.0.2",
            port=6653
        ),
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )

    net.start()

    print("Mininet network started")

    # FORCE OpenFlow13
    for s in net.switches:
        s.cmd(f"ovs-vsctl set bridge {s.name} protocols=OpenFlow13")

    return net
# -------------------------------------------------
# NETCFG
# -------------------------------------------------

def push_netcfg():

    print("Deploying netcfg")

    os.system(
        "curl --user onos:rocks "
        "-H 'Content-Type: application/json' "
        "-X POST "
        "http://localhost:8181/onos/v1/network/configuration "
        "-d @onos/netcfg.json"
    )


# -------------------------------------------------
# SERVICES
# -------------------------------------------------

def start_services(net):

    print("Starting services")

    net.get("h70").cmd("python3 services/webserver.py &")
    net.get("h71").cmd("python3 services/dns.py &")
    net.get("h72").cmd("python3 services/api.py &")

    net.get("h80").cmd("python3 ids/gnn_ids.py &")

    net.get("h81").cmd("python3 services/honeypot.py &")

    net.get("h82").cmd("python3 monitor/capture.py &")


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

def main():

    clean_mininet()

    wait_onos_ready()

    enable_apps()

    net = start_network()

    time.sleep(5)

    wait_devices()

    time.sleep(3)

    push_netcfg()

    # print("*** Discovering hosts")
    # net.pingAll(timeout='1')
    print("*** Host discovery")

    hosts = net.hosts

    for i, h in enumerate(hosts):
        target = hosts[(i+1) % len(hosts)]
        h.cmd(f"ping -c1 -W1 {target.IP()} &")

    start_services(net)

    time.sleep(10)

    start_normal_traffic(net)
    subprocess.Popen(["python3", "onos/highlight_bot.py"])
    print("\nCyber-range ready.")
    print("Launch attacks using attack framework.\n")

    CLI(net)

    net.stop()


if __name__ == "__main__":

    setLogLevel("info")

    main()