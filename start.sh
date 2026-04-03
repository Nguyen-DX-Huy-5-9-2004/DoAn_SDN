#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

sudo systemctl stop docker || true
sudo systemctl stop openvswitch-switch || true
sudo ip -all netns delete || true
docker rm -f web1 db1 proxy1 2>/dev/null || true
sudo fuser -k 6653/tcp 6633/tcp 8181/tcp 8000/tcp 8050/tcp || true
# Tránh pkill -f mininet vì có thể match nhầm và tự kill shell/script.
sudo pkill -9 -x mnexec || true
sudo pkill -f "monitor/onos_metrics_collector.py" || true
sudo pkill -f "dashboard/server.py" || true
sudo mn -c 2>/dev/null || true
docker rm -f onos 2>/dev/null || true
docker build -t doan_sdn_web1:py39 -f docker/web1/Dockerfile .
docker build -t doan_sdn_proxy1:latest -f docker/proxy/Dockerfile .

mkdir -p "$SCRIPT_DIR/docker/proxy/certs"
openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "$SCRIPT_DIR/docker/proxy/certs/server.key" \
  -out "$SCRIPT_DIR/docker/proxy/certs/server.crt" \
  -subj "/C=VN/ST=HN/L=HaNoi/O=DoAnSDN/OU=Lab/CN=10.0.0.10"

sudo systemctl start openvswitch-switch
sudo systemctl start docker
docker run -t -d --name onos \
  -m 3g \
  -p 8181:8181 -p 6653:6653 -p 8101:8101 \
  -e "JAVA_OPTS=-Xms2G -Xmx3G" \
  -e "ONOS_APPS=drivers,openflow,fwd,proxyarp,gui" \
  onosproject/onos:latest
sleep 5
mkdir -p "$SCRIPT_DIR/monitor/runtime"

sudo env \
  PYTHONPATH="${SCRIPT_DIR}/sdn_env/lib/python3.12/site-packages" \
  "${SCRIPT_DIR}/sdn_env/bin/python3" "${SCRIPT_DIR}/monitor/onos_metrics_collector.py" \
  > /tmp/onos_metrics_collector.log 2>&1 &
ONOS_COLLECTOR_PID=$!

sudo env \
  PYTHONPATH="${SCRIPT_DIR}/sdn_env/lib/python3.12/site-packages" \
  "${SCRIPT_DIR}/sdn_env/bin/python3" "${SCRIPT_DIR}/dashboard/server.py" \
  > /tmp/sdn_dashboard.log 2>&1 &
DASHBOARD_PID=$!

cleanup() {
  sudo kill "$ONOS_COLLECTOR_PID" "$DASHBOARD_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# sudo xóa DISPLAY/XAUTHORITY mặc định → trình duyệt từ h60 không mở được; truyền rõ + PYTHONPATH theo thư mục clone.
sudo env \
  DISPLAY="${DISPLAY:-:0}" \
  XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
  PYTHONUNBUFFERED=1 \
  "PYTHONPATH=${SCRIPT_DIR}/sdn_env/lib/python3.12/site-packages" \
  "${SCRIPT_DIR}/sdn_env/bin/python3" "${SCRIPT_DIR}/system.py"