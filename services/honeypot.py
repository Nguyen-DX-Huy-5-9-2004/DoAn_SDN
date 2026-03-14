import socket

HOST = "0.0.0.0"
PORT = 8080

s = socket.socket()

s.bind((HOST, PORT))
s.listen(5)

print("Honeypot running")

while True:

    conn, addr = s.accept()

    print("Connection from", addr)

    conn.send(b"Fake service\n")

    conn.close()