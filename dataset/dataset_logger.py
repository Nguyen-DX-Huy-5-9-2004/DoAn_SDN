import os
import time


DATASET_FILE = "dataset/labels.csv"


def log_attack(name):

    os.makedirs("dataset", exist_ok=True)

    if not os.path.exists(DATASET_FILE):

        with open(DATASET_FILE, "w") as f:

            f.write("timestamp,attack\n")

    with open(DATASET_FILE, "a") as f:

        f.write(f"{int(time.time())},{name}\n")

    print("Dataset label:", name)