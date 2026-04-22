import pandas as pd

df = pd.read_csv("dataset/features.csv")

window = 50

for i in range(len(df) - window):

    segment = df[i:i+window]

    packet_rate = len(segment)

    if packet_rate > 40:
        print("Possible DDoS attack")