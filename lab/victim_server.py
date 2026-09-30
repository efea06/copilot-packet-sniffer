#!/usr/bin/env python3
"""Tiny "victim" web server for the lab. Binds to 127.0.0.1 ONLY."""
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST, PORT = "127.0.0.1", 8080


class Handler(BaseHTTPRequestHandler):
    def _reply(self):
        body = b"hello from the lab victim server\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "sessionid=FAKE-SERVER-SESSION-123; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._reply()


if __name__ == "__main__":
    print(f"Victim server on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    HTTPServer((HOST, PORT), Handler).serve_forever()
