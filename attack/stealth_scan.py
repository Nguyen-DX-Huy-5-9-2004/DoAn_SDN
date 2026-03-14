# attack/stealth_scan.py

import time


def run(net, target="10.0.0.100"):

    print("\nStarting STEALTH scan\n")

    bots = list(range(1, 20))

    for b in bots:

        bot = net.get(f"h{b}")

        bot.cmd(f"nmap -sS {target} &")

        print("Bot", b, "scanning")

        time.sleep(1.5)

    print("Stealth scan finished\n")

'''Mô phỏng stealth scan (quét lén lút).
Đặc điểm:
- Sử dụng SYN scan (nmap -sS) để quét cổng mà không hoàn thành handshake TCP.
- Các bot quét lần lượt, cách nhau vài giây → tránh bị IDS phát hiện.
Pattern này thường được dùng để thăm dò hệ thống trước khi tấn công.
IDS thường dựa vào pattern này để phát hiện reconnaissance.
-server nào đang chạy
-port nào đang mở
-dịch vụ nào tồn tại'''
