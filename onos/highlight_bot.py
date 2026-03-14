import requests
import time

ONOS = "http://localhost:8181/onos/v1/ui/highlight"
auth = ("onos","rocks")

links = [
 ("of:0000000000000004/1","of:0000000000000002/1"),
]

def highlight(color):

 data = {
  "event":"highlight",
  "links":[]
 }

 for src,dst in links:

  data["links"].append({
   "src":src,
   "dst":dst,
   "type":color
  })

 requests.post(ONOS,auth=auth,json=data)

while True:

 highlight("primary")
 time.sleep(0.5)

 highlight("default")
 time.sleep(0.5)