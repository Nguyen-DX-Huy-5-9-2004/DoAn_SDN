from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer

PORT = 80

Handler = SimpleHTTPRequestHandler

with TCPServer(("", PORT), Handler) as httpd:
    print("Web server running")
    httpd.serve_forever()