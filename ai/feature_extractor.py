import pyshark
import pandas as pd

capture = pyshark.FileCapture("dataset/traffic.pcap")

records = []

for pkt in capture:

    try:

        records.append({

            "length": pkt.length,
            "protocol": pkt.highest_layer,
            "src": pkt.ip.src,
            "dst": pkt.ip.dst

        })

    except:
        pass

df = pd.DataFrame(records)

df.to_csv("dataset/features.csv")