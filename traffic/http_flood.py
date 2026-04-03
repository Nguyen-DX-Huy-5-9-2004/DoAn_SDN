import requests
import sys
import urllib3

target = sys.argv[1]
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

while True:

    try:
        requests.get(target, verify=False, timeout=2)
    except:
        pass