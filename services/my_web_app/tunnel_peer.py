"""Dùng với: docker exec -i mn.web1 python3 /app/tunnel_peer.py <port>
Nối stdio với TCP tới 127.0.0.1:<port> (Django runserver) để host proxy qua docker exec."""
import socket
import sys
import threading


def main():
    port = int(sys.argv[1])
    remote = socket.create_connection(("127.0.0.1", port))
    inp = sys.stdin.buffer
    out = sys.stdout.buffer

    def up():
        try:
            while True:
                chunk = inp.read(8192)
                if not chunk:
                    break
                remote.sendall(chunk)
        finally:
            try:
                remote.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    th = threading.Thread(target=up, daemon=True)
    th.start()
    try:
        while True:
            chunk = remote.recv(65536)
            if not chunk:
                break
            out.write(chunk)
            out.flush()
    finally:
        th.join(timeout=1)
        remote.close()


if __name__ == "__main__":
    main()
