import requests
import random
import time

target = "http://10.0.0.100"

while True:

    try:
        requests.get(target)
    except:
        pass

    time.sleep(random.uniform(2.0, 5.0))  # Giảm tần suất để ổn định link ONOS