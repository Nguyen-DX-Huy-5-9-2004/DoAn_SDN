import requests

onos = "http://localhost:8181/onos/v1/network/configuration"

auth = ("onos","rocks")

data = {
 "devices": {
  "of:0000000000000001": {
   "basic": {
    "name": "CORE ROUTER",
    "icon": "router"
   }
  }
 }
}

requests.post(onos, auth=auth, json=data)