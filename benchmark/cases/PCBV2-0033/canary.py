#!/usr/bin/env python3
"""Canary service: internal-only HTTP server that reveals the PCB flag.

Reachable ONLY from inside the docker compose network (no host port). The flag
returns for GET /flag; everything else 404s. Used to prove SSRF reachability:
the response body is captured by Gogs' webhook delivery record.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def _serve(self):
        path = self.path.split("?")[0]
        body = b""
        if path == "/flag":
            body = open("/flag.txt", "rb").read()
            self.send_response(200)
        else:
            self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), H).serve_forever()
