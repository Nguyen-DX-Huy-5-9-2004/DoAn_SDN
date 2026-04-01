import requests
import json

ONOS = "http://localhost:8181/onos/v1"

auth = ("onos", "rocks")

bot_host = "00:00:00:00:00:02/None"

data = {
    "type": "warning",
    "message": "BOT DETECTED",
    "severity": "CRITICAL"
}

r = requests.post(
    ONOS + "/core/messages",
    auth=auth,
    json=data
)

print(r.status_code)