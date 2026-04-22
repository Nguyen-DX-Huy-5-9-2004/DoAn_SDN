#!/usr/bin/env python3
import argparse
import socket
import time

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.0.0.10", 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Open/check HTTPS web service from any Mininet host namespace."
    )
    parser.add_argument("--url", default="https://10.0.0.10", help="Target base URL")
    parser.add_argument("--path", default="/", help="HTTP path")
    parser.add_argument("--interval", type=float, default=0, help="Repeat interval seconds (0 means once)")
    parser.add_argument("--timeout", type=float, default=8, help="HTTP timeout")
    parser.add_argument("--show-body", type=int, default=200, help="Max body chars to print")
    args = parser.parse_args()

    url = args.url.rstrip("/") + "/" + args.path.lstrip("/")
    print(f"[OPEN-WEB] Host namespace IP: {local_ip()}")
    print(f"[OPEN-WEB] Request URL: {url}")

    while True:
        try:
            r = requests.get(url, verify=False, timeout=args.timeout)
            body = (r.text or "").replace("\n", " ")
            print(f"[OPEN-WEB] status={r.status_code} len={len(r.text)}")
            if args.show_body > 0:
                print(f"[OPEN-WEB] body[:{args.show_body}]={body[:args.show_body]}")
        except Exception as e:
            print(f"[OPEN-WEB] request failed: {e}")

        if args.interval <= 0:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
