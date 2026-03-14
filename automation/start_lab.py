import os
import time

print("=== Starting SDN DDoS Lab ===")

print("Starting ONOS container...")
os.system("sudo docker start onos-controller")

time.sleep(10)

print("Launching Mininet topology...")
os.system("sudo mn --custom topology/botnet_topo.py --topo botnet --controller=remote,ip=127.0.0.1 --switch ovs,protocols=OpenFlow13")

print("Lab started.")