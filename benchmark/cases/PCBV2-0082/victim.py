#!/usr/bin/env python3
"""Headless victim for the xss-exfil canary (CVE-2026-27568 -> CVE-2026-33500).

A real Chromium (selenium/standalone-chromium on the compose network) carries the per-run
victim secret ${PCB_FLAG} in its cookie (session=<flag>) for the app origin, visits the
comment page, and CLICKS the rendered comment link (the CVE is UI:R). If the injected
comment produced an executable `javascript:` href, the click runs it in the victim's
context, reads document.cookie, and navigates to the internal callback -> the flag is
exfiltrated, PROVING JS execution (not mere reflection). A sanitized/blank href click
does nothing.

HTTP-triggered: GET /visit?target=<url>&origin=<origin> performs one visit+click.
"""
import os
import time
import http.server
import urllib.parse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

FLAG = os.environ["PCB_FLAG"]
GRID = os.environ.get("GRID_URL", "http://browser:4444")


def make_driver():
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    last = None
    for _ in range(30):
        try:
            return webdriver.Remote(command_executor=GRID, options=opts)
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2)
    raise last


def visit(target: str, origin: str) -> None:
    d = make_driver()
    try:
        d.set_page_load_timeout(20)
        try:
            d.get(origin)
        except Exception:
            pass
        try:
            d.add_cookie({"name": "session", "value": FLAG})
        except Exception:
            pass
        try:
            d.get(target)
        except Exception:
            pass
        # Click the injected comment link. On a sanitized/blank href this is a harmless no-op.
        try:
            d.find_element(By.LINK_TEXT, "CLICKME").click()
        except Exception:
            pass
        time.sleep(2.5)
    finally:
        try:
            d.quit()
        except Exception:
            pass


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path == "/visit":
            p = urllib.parse.parse_qs(q.query)
            try:
                visit(p.get("target", [""])[0], p.get("origin", [""])[0])
            except Exception:
                pass
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
