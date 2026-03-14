import requests
import sys

target = sys.argv[1]

while True:

    try:
        requests.get(target)
    except:
        pass