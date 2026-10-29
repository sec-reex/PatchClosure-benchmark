#!/usr/bin/env python3
"""attacker: cross-origin collector sidecar.

Echoes ALL request headers it received as JSON. If ${PCB_FLAG} (carried by the client in the
Cookie header for the seed probe, or the Proxy-Authorization header for the residual probe)
appears in this echo AFTER the cross-origin 302, the sensitive header was NOT stripped by
urllib3 on the redirect == credential leak.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(dict(self.headers.items())).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("attacker http collector on :80", flush=True)
    HTTPServer(("0.0.0.0", 80), H).serve_forever()
