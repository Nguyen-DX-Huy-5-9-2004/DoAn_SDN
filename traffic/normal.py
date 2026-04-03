import requests
import random
import time
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

target = sys.argv[1] if len(sys.argv) > 1 else "https://10.0.0.10"

while True:

    try:
        requests.get(target, verify=False, timeout=3)
    except:
        pass

    time.sleep(random.uniform(2.0, 5.0))  # Giảm tần suất để ổn định link ONOS