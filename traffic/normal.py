import requests
import random
import time

target = "http://10.0.0.1"

while True:

    try:
        requests.get(target)
    except:
        pass

    time.sleep(random.uniform(0.5,2))