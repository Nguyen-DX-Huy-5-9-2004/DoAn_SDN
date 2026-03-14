# attack/burst_attack.py

import time


def run(net, target="10.0.0.100", burst_duration=5, pause=10):

    print("\nStarting BURST attack\n")

    bots = list(range(1, 51))

    for cycle in range(3):

        print("Burst cycle", cycle + 1)

        for b in bots:

            bot = net.get(f"h{b}")

            bot.cmd(f"python3 traffic/syn_flood.py {target} &")

        time.sleep(burst_duration)

        print("Stopping burst")

        for b in bots:

            bot = net.get(f"h{b}")

            bot.cmd("pkill -f syn_flood.py")

        time.sleep(pause)

    print("Burst attack finished\n")

'''Mô phỏng burst traffic spike.

Pattern:

normal
↓
sudden spike
↓
stop
↓
spike again

IDS rất hay dùng pattern này để test.'''