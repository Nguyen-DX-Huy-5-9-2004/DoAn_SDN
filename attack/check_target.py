#!/usr/bin/env python3
"""
Kiểm tra kết nối đến target IP/hostname:port
"""

import argparse
import socket
import ssl
import subprocess
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def is_ip_address(value):
    """Kiểm tra xem giá trị có phải địa chỉ IP hay không"""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


def ping_target(target, count=3):
    """Ping target để kiểm tra kết nối mạng"""
    print(f"[1/3] Pinging {target}...")
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), target],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"Ping thành công: {target} is reachable")
            return True
        print(f"Ping thất bại: {target} is not reachable")
        return False
    except Exception as e:
        print(f"Lỗi ping: {e}")
        return False


def check_port(target, port, timeout=5):
    """Kiểm tra port có mở không bằng socket"""
    print(f"[2/3] Checking port {port} on {target}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            print(f"Port {port} is OPEN on {target}")
            return True
        print(f"Port {port} is CLOSED on {target}")
        return False
    except Exception as e:
        print(f"Lỗi kiểm tra port: {e}")
        return False


def check_http(target, port, path='/', use_ssl=False, host_header=None, timeout=5):
    """Thử HTTP/HTTPS request để kiểm tra web service"""
    scheme = 'https' if use_ssl else 'http'
    url = f"{scheme}://{target}:{port}{path}"
    print(f"[3/3] Checking {scheme.upper()} service at {url}...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        if host_header:
            headers['Host'] = host_header

        req = Request(url, headers=headers)
        context = None
        if use_ssl:
            context = ssl.create_default_context()
            if host_header and host_header != target:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

        response = urlopen(req, timeout=timeout, context=context)
        status_code = response.getcode()
        print('   HTTP service is running!')
        print(f'   Status: {status_code}')
        print(f'   Headers: {dict(response.headers)}')
        return True
    except HTTPError as e:
        print(f'   HTTP service trả về lỗi: {e.code} - {e.reason}')
        return True
    except URLError as e:
        print(f'  HTTP service không khả dụng: {e.reason}')
        return False
    except Exception as e:
        print(f'  Lỗi HTTP: {e}')
        return False


def detect_port(target, host_header=None, path='/', timeout=5):
    """Tự dò port 443/80 bằng HTTPS trước, sau đó HTTP."""
    print('[0/3] Tự dò port 443/80...')
    for port, use_ssl in [(443, True), (80, False)]:
        if check_port(target, port, timeout=timeout):
            if host_header is None and not is_ip_address(target):
                host_header = target
            if check_http(target, port, path=path, use_ssl=use_ssl, host_header=host_header, timeout=timeout):
                return port, use_ssl
            print(f'   {"HTTPS" if use_ssl else "HTTP"} trên port {port} không phản hồi đúng.')
        else:
            print(f'   Bỏ port {port} vì không mở.')
    return None, None


def parse_args():
    parser = argparse.ArgumentParser(description='Kiểm tra target IP/hostname:port')
    parser.add_argument('target', help='IP hoặc hostname của target')
    parser.add_argument('-p', '--port', type=int, default=None, help='Port của target (mặc định 80 hoặc 443 khi --ssl)')
    parser.add_argument('-H', '--hostname', help='Hostname để gửi Host header / SNI')
    parser.add_argument('--path', default='/', help='Path để kiểm tra HTTP/HTTPS')
    parser.add_argument('--ssl', action='store_true', help='Dùng HTTPS thay vì HTTP')
    parser.add_argument('--auto-port', action='store_true', help='Tự dò port 443/80 nếu không rõ port')
    parser.add_argument('--skip-ping', action='store_true', help='Bỏ qua bước ping nếu ICMP bị chặn')
    return parser.parse_args()


def main():
    args = parse_args()
    target = args.target
    host_header = args.hostname
    if host_header is None and not is_ip_address(target):
        host_header = target

    if args.port is None and args.auto_port:
        port, use_ssl = detect_port(target, host_header=host_header, path=args.path)
        if port is None:
            print('\n[!] Không tìm được port 443 hoặc 80 hoạt động cho target này.')
            sys.exit(1)
    else:
        port = args.port if args.port is not None else (443 if args.ssl else 80)
        use_ssl = args.ssl or port == 443

    print('=' * 70)
    print('TARGET CHECKER')
    print('=' * 70)
    print(f'Target: {target}')
    print(f'Port: {port}')
    print(f'Use SSL: {use_ssl}')
    print(f'Host header: {host_header}')
    print(f'Path: {args.path}')
    print('=' * 70)
    print()

    ping_ok = True
    if not args.skip_ping:
        ping_ok = ping_target(target)
        print()

    port_ok = check_port(target, port)
    print()

    http_ok = check_http(target, port, path=args.path, use_ssl=use_ssl, host_header=host_header)
    print()

    print('=' * 70)
    print('SUMMARY')
    print('=' * 70)
    print(f'Ping: {" OK" if ping_ok else " FAIL"}')
    print(f'Port {port}: {" OPEN" if port_ok else " CLOSED"}')
    print(f'HTTP: {" RUNNING" if http_ok else " NOT RUNNING"}')
    print('=' * 70)

    if not ping_ok:
        print('[!] Ping failed nhưng target vẫn có thể mở port/HTTP. Nếu ICMP bị chặn thì vẫn có thể chạy attack.')
    if port_ok and http_ok:
        print('\n[+] Target có thể truy cập được trên port và HTTP/HTTPS.')
        sys.exit(0)
    print('\n[!] Target kiểm tra chưa hoàn toàn thành công.')
    sys.exit(1)


if __name__ == '__main__':
    main()

if __name__ == "__main__":
    sys.exit(main())
