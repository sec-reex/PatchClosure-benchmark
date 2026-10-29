#!/usr/bin/env python3
"""Headless victim for the xss-exfil canary (CVE-2024-10099 -> CVE-2025-6092).

A real chromium browser (in the compose network) carries the per-run victim secret ${PCB_FLAG}
in its cookie (session=<flag>) for the app origin, then NAVIGATES to the /view URL of an uploaded
file (this is the stored-XSS trigger: the victim views the attacker's file). If /view served the
file as a renderable type (text/html, image/svg+xml, ...), the browser RENDERS it and runs any
embedded <script>, which reads document.cookie and navigates to the internal callback -> the flag
is exfiltrated, PROVING JS execution. If /view forced a download (application/octet-stream), the
browser saves the file, nothing renders, no script runs -> no exfil.

HTTP-triggered: GET /visit?target=<view-url>&origin=<origin> performs one visit.
"""
import os
import http.server
import urllib.parse
from playwright.sync_api import sync_playwright

FLAG = os.environ["PCB_FLAG"]

_pw = sync_playwright().start()
# accept_downloads so an octet-stream response is consumed as a (harmless) download rather than
# hanging the navigation; the point is that NO script runs on a download.
_browser = _pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])


def visit(target: str, origin: str) -> None:
    ctx = _browser.new_context(accept_downloads=True)
    # Plant the victim-only secret in the browser (readable via document.cookie on the app origin).
    ctx.add_cookies([{"name": "session", "value": FLAG, "url": origin}])
    page = ctx.new_page()
    try:
        # Renderable types load & execute here. octet-stream aborts navigation as a download.
        page.goto(target, wait_until="load", timeout=15000)
    except Exception:
        pass
    page.wait_for_timeout(2500)  # let any script-triggered navigation to the callback fire
    try:
        ctx.close()
    except Exception:
        pass


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path == "/visit":
            p = urllib.parse.parse_qs(q.query)
            visit(p["target"][0], p["origin"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"done")
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
    http.server.HTTPServer(("0.0.0.0", 8070), H).serve_forever()
