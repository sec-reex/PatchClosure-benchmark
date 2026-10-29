#!/usr/bin/env python3
"""Headless victim for the Sanitize foreign-content -> noscript mutation-XSS canary
(CVE-2020-4054 -> CVE-2023-23627).

A real Chromium browser (driven via a selenium/standalone-chromium grid on the compose network)
carries the per-run victim secret ${PCB_FLAG} in its cookie (session=<flag>) for the app origin,
then views the Sanitize-sink page (`/?html=<payload>`). The app has already run REAL Sanitize over
the payload; the browser now PARSES that sanitized output *with scripting enabled*.

If Sanitize's output MUTATES on parse into a live `<img src=x onerror=...>` -- because a
non-allowlisted <math>/<svg> foreign-content wrapper leaked its contents (v0), or because a
<noscript> element is parsed as raw text by the scripting-enabled browser but was parsed as markup
by scripting-disabled Nokogiri (v1) -- the onerror fires on page LOAD, reads document.cookie and
navigates to the internal callback -> the flag is exfiltrated, PROVING JS execution (not mere
reflection). An escaped/inert output does nothing.

HTTP-triggered: GET /visit?target=<url>&origin=<origin>&mode=load performs one visit.
"""
import os
import time
import http.server
import urllib.parse

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains

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


def visit(target: str, origin: str, mode: str) -> None:
    d = make_driver()
    try:
        d.set_page_load_timeout(20)
        # Plant the victim-only secret on the app origin (readable via document.cookie).
        try:
            d.get(origin)
        except Exception:
            pass
        try:
            d.add_cookie({"name": "session", "value": FLAG})
        except Exception:
            pass
        # Load the sanitized page. A mutation-XSS <img onerror> fires here, on load.
        try:
            d.get(target)
        except Exception:
            pass  # a load-time onerror navigation can abort the load -- that IS the exploit firing
        time.sleep(3)
        if mode == "hover":
            try:
                el = d.find_element(By.CSS_SELECTOR, "#content")
                ActionChains(d).move_to_element(el).perform()
            except Exception:
                pass
            time.sleep(2)
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
            visit(p["target"][0], p["origin"][0], p.get("mode", ["load"])[0])
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
