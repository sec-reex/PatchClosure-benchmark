#!/usr/bin/env python3
"""Headless victim for SiYuan getDynamicIcon SVG XSS (CVE-2026-29183 -> CVE-2026-31807).

Navigates the kernel's image/svg+xml response as a DOCUMENT (not <img>), plants
start-time ${PCB_FLAG} as a cookie on the SiYuan origin, waits for SMIL
(<animate begin=0s> writes href), then clicks the <a> so javascript: runs in
the SiYuan origin and exfiltrates document.cookie to callback.
"""
import os
import http.server
import urllib.parse

from playwright.sync_api import sync_playwright

FLAG = os.environ["PCB_FLAG"]

_pw = sync_playwright().start()
_browser = _pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])


def visit(target: str, origin: str) -> None:
    ctx = _browser.new_context()
    ctx.add_cookies([{"name": "siyuan-session", "value": FLAG, "url": origin}])
    page = ctx.new_page()
    try:
        # Document navigation of the SVG URL — <img> would not run javascript:.
        page.goto(target, wait_until="load", timeout=20000)
    except Exception:
        pass
    # SMIL begin=0s / fill=freeze writes href before the click.
    page.wait_for_timeout(1500)
    try:
        page.locator("a").first.click(timeout=4000)
    except Exception:
        try:
            page.locator("text").last.click(timeout=2000)
        except Exception:
            try:
                page.mouse.click(256, 256)
            except Exception:
                pass
    page.wait_for_timeout(3000)
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
