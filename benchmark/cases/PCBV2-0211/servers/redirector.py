#!/usr/bin/env python3
"""redirector: cross-ORIGIN redirector host.

GET /redir  ->  302 Location: http://attacker/collect   (DIFFERENT host => cross-origin).
urllib3's PoolManager evaluates `not conn.is_same_host(redirect_location)` against the pool
for host "redirector"; "attacker" is a different netloc, so the cross-origin header strip
(remove_headers_on_redirect) fires. This is the genuine cross-origin boundary of the case.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://attacker/collect")
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("redirector http on :80 -> http://attacker/collect", flush=True)
    HTTPServer(("0.0.0.0", 80), H).serve_forever()
