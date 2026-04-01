import random
import subprocess
import time

clients = ["h60","h61","h62","h63","h64","h65"]

while True:
    c = random.choice(clients)

    subprocess.run(
        f"mininet> {c} curl 10.0.0.70",
        shell=True
    )

    time.sleep(random.uniform(1,3))