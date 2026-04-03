import csv
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

import requests


ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT.parent / "monitor" / "runtime"
ONOS_FILE = RUNTIME / "onos_metrics.json"
HTTP_LOG_FILE = RUNTIME / "http_requests.csv"
WEB1_STATUS_URL = os.environ.get("WEB1_STATUS_URL", "http://10.0.0.11/api/system_status")


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, code=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._send_html((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
            return
        if path == "/api/onos":
            if ONOS_FILE.exists():
                self._send_json(json.loads(ONOS_FILE.read_text(encoding="utf-8")))
            else:
                self._send_json({"ports": []})
            return
        if path == "/api/system":
            try:
                r = requests.get(WEB1_STATUS_URL, timeout=3)
                self._send_json(r.json())
            except Exception as e:
                self._send_json({"error": str(e), "cpu_percent": 0, "ram_percent": 0, "connections": 0})
            return
        if path == "/api/http_logs":
            rows = []
            if HTTP_LOG_FILE.exists():
                with open(HTTP_LOG_FILE, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)[-100:]
            self._send_json({"rows": rows})
            return
        self._send_json({"error": "not found"}, code=404)


def main():
    os.makedirs(RUNTIME, exist_ok=True)
    server = HTTPServer(("127.0.0.1", 8050), Handler)
    print("[DASHBOARD] http://127.0.0.1:8050")
    server.serve_forever()


if __name__ == "__main__":
    main()
