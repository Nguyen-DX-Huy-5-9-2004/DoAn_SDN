import os
import time

filename = "dataset/traffic_" + str(int(time.time())) + ".pcap"

print("Capturing traffic:", filename)

os.system(
    f"tcpdump -i h21-eth0 -c 100000 -w {filename}"
)
