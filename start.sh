#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

sudo systemctl stop docker
sudo systemctl stop openvswitch-switch
sudo ip -all netns delete
docker rm -f web1 db1 2>/dev/null
sudo fuser -k 6653/tcp 6633/tcp 8181/tcp 8000/tcp
sudo pkill -9 -f mininet
sudo pkill -9 -f mnexec
sudo mn -c 2>/dev/null
docker rm -f onos 2>/dev/null
docker build -t doan_sdn_web1:py39 -f docker/web1/Dockerfile .
sudo systemctl start openvswitch-switch
sudo systemctl start docker
docker run -t -d --name onos \
  -m 3g \
  -p 8181:8181 -p 6653:6653 -p 8101:8101 \
  -e "JAVA_OPTS=-Xms2G -Xmx3G" \
  -e "ONOS_APPS=drivers,openflow,fwd,proxyarp,gui" \
  onosproject/onos:latest
sleep 5
# sudo xóa DISPLAY/XAUTHORITY mặc định → trình duyệt từ h60 không mở được; truyền rõ + PYTHONPATH theo thư mục clone.
sudo env \
  DISPLAY="${DISPLAY:-:0}" \
  XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
  "PYTHONPATH=${SCRIPT_DIR}/sdn_env/lib/python3.12/site-packages" \
  "${SCRIPT_DIR}/sdn_env/bin/python3" "${SCRIPT_DIR}/system.py"