import random
import time
from dataset.dataset_logger import log_attack


def activate_bot(net, bot_id, script, target):

    bot = net.get(f"h{bot_id}")

    bot.cmd(f"python3 {script} {target} &")


def random_bot_activation(net, target):

    print("Random bot activation")

    bots = list(range(1, 51))

    random.shuffle(bots)

    for b in bots:

        activate_bot(net, b, "traffic/syn_flood.py", target)

        time.sleep(random.uniform(0.5, 2))

    log_attack("random_botnet")


def multi_wave_attack(net, target):

    print("Multi wave attack")

    for wave in range(5):

        print("Wave", wave)

        for i in range(1 + wave * 10, 11 + wave * 10):

            activate_bot(net, i, "traffic/syn_flood.py", target)

        time.sleep(10)

    log_attack("multi_wave")


def syn_flood(net, target):

    print("SYN flood")

    for i in range(1, 51):

        activate_bot(net, i, "traffic/syn_flood.py", target)

    log_attack("syn_flood")


def udp_flood(net, target):

    print("UDP flood")

    for i in range(1, 51):

        activate_bot(net, i, "traffic/udp_flood.py", target)

    log_attack("udp_flood")


def http_flood(net, target):

    print("HTTP flood")

    for i in range(1, 51):

        activate_bot(net, i, "traffic/http_flood.py", target)

    log_attack("http_flood")


def slowloris(net, target):

    print("Slowloris simulation")

    for i in range(1, 30):

        activate_bot(net, i, "traffic/slowloris.py", target)

    log_attack("slowloris")