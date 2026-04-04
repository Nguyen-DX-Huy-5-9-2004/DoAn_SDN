import csv
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import requests


ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT.parent / "monitor" / "runtime"
ONOS_FILE = RUNTIME / "onos_metrics.json"
HTTP_LOG_FILE = RUNTIME / "http_requests.csv"
WEB1_STATUS_URL = os.environ.get("WEB1_STATUS_URL", "http://127.0.0.1:8000/api/system_status")

# Cache configuration
CACHE_EXPIRY = 1.5  # seconds
_cache = {
    "onos": {"data": {"ports": []}, "ts": 0, "status": "offline"},
    "system": {"data": {"cpu_percent": 0, "ram_percent": 0, "connections": 0}, "ts": 0, "status": "offline"},
    "logs": {"data": {"rows": []}, "ts": 0}
}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Optional: Disable default logging to keep terminal clean
        # or implement a custom log file rotation for the server itself.
        pass

    def _send_json(self, payload, code=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, content_type):
        if not path.exists():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _fetch_with_retry(self, url, retries=2, backoff=0.2):
        for i in range(retries):
            try:
                r = requests.get(url, timeout=1.5)
                if r.status_code == 200:
                    return r.json()
            except Exception:
                pass
            if i < retries - 1:
                time.sleep(backoff * (i + 1))
        return None

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        now = time.time()

        if path == "/":
            self._send_html((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
            return
        
        if path == "/chart.js":
            self._send_file(ROOT / "static" / "chart.js", "application/javascript")
            return

        if path == "/api/onos":
            if now - _cache["onos"]["ts"] < CACHE_EXPIRY:
                self._send_json({**_cache["onos"]["data"], "status": _cache["onos"]["status"]})
                return
            
            data = {"ports": []}
            status = "offline"
            if ONOS_FILE.exists():
                try:
                    # Check if file is recent (less than 10s old)
                    if now - ONOS_FILE.stat().st_mtime < 10:
                        data = json.loads(ONOS_FILE.read_text(encoding="utf-8"))
                        status = "online"
                except Exception:
                    pass
            _cache["onos"] = {"data": data, "ts": now, "status": status}
            self._send_json({**data, "status": status})
            return

        if path == "/api/system":
            if now - _cache["system"]["ts"] < CACHE_EXPIRY:
                self._send_json({**_cache["system"]["data"], "status": _cache["system"]["status"]})
                return
            
            # Debug log to console
            print(f"[DASHBOARD] Fetching status from: {WEB1_STATUS_URL}")
            data = self._fetch_with_retry(WEB1_STATUS_URL)
            if data:
                print(f"[DASHBOARD] Web1 status OK: {data.get('hostname', 'unknown')}")
                status = "online"
            else:
                print(f"[DASHBOARD] Web1 status FAILED from {WEB1_STATUS_URL}")
                status = "offline"
                data = _cache["system"]["data"]
            
            _cache["system"] = {"data": data, "ts": now, "status": status}
            self._send_json({**data, "status": status})
            return

        if path == "/api/http_logs":
            if now - _cache["logs"]["ts"] < CACHE_EXPIRY:
                self._send_json(_cache["logs"]["data"])
                return
            
            rows = []
            if HTTP_LOG_FILE.exists():
                try:
                    with open(HTTP_LOG_FILE, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        rows = list(reader)[-50:]
                except Exception:
                    pass
            data = {"rows": rows}
            _cache["logs"] = {"data": data, "ts": now}
            self._send_json(data)
            return
        
        self._send_json({"error": "not found"}, code=404)


def main():
    os.makedirs(RUNTIME, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 8050), Handler)
    print("[DASHBOARD] http://127.0.0.1:8050 (Multi-threaded)")
    server.serve_forever()


if __name__ == "__main__":
    main()
