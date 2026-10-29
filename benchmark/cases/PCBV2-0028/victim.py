#!/usr/bin/env python3
"""Headless victim for the xss-exfil canary (CVE-2019-19491 -> CVE-2019-20381), REAL TestLink.

A REAL Chromium (driven via a selenium/standalone-chromium Grid in the compose network -- the
mcr.microsoft.com/playwright image is unreachable in this infra) LOGS INTO the REAL TestLink
(admin/admin) because index.php reflects `reqURI` into main.tpl's `<iframe src>` ONLY for an
authenticated session (unauthenticated requests are redirected to login.php before main.tpl renders
-- the CVE is an authenticated reflected XSS, cf. ExploitDB 47702's session cookies). After login
the victim plants the per-run secret ${PCB_FLAG} in a `session` cookie (readable via document.cookie
for the app origin) and VISITS the attacker's crafted reqURI URL. If reqURI reflects into an
executable `javascript:` scheme, the iframe runs it in the victim's origin, reads document.cookie,
and navigates to the internal callback -> the flag is exfiltrated, PROVING JS EXECUTION (not mere
reflection). A sanitized/blanked reqURI (guard replaced it with mainPage.php) does nothing.

This is a REFLECTED XSS (UI:R): exploitation = a logged-in victim visiting the crafted URL; the
iframe's javascript: src fires on load, so no click is needed on the payload page.

HTTP-triggered: GET /visit?target=<url>&origin=<origin> performs one login+visit.
"""
import os
import sys
import time
import subprocess
import http.server
import urllib.parse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

FLAG = os.environ["PCB_FLAG"]
GRID = os.environ.get("SELENIUM_URL", "http://chromium:4444")
TL_USER = os.environ.get("TL_USER", "admin")
TL_PASS = os.environ.get("TL_PASS", "admin")


def _driver():
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    # "none" -> driver.get() returns as soon as navigation starts, without blocking on subframe
    # (iframe) loads. Essential here: the reflected <iframe src="javascript:..."> redirects itself
    # to the callback, so a "normal" strategy would hang on the never-"finishing" load.
    opts.page_load_strategy = "none"
    last = None
    for _ in range(30):
        try:
            d = webdriver.Remote(command_executor=GRID, options=opts)
            d.set_page_load_timeout(30)
            return d
        except Exception as e:  # grid not up yet
            last = e
            time.sleep(2)
    raise last


def _login(d, base):
    """Log into the REAL TestLink (admin/admin) so index.php will render main.tpl for this session."""
    d.get(base + "/login.php")
    WebDriverWait(d, 25).until(EC.presence_of_element_located((By.NAME, "tl_login")))
    d.find_element(By.NAME, "tl_login").send_keys(TL_USER)
    d.find_element(By.NAME, "tl_password").send_keys(TL_PASS)
    d.find_element(By.NAME, "tl_password").submit()
    # Let the login POST + redirect back to index.php settle (page_load_strategy="none").
    time.sleep(5.0)


def visit(target: str, origin: str) -> None:
    d = _driver()
    try:
        base = origin.rstrip("/")
        # 1) Authenticate against the REAL TestLink (reflection needs a live session).
        _login(d, base)
        # 2) Plant the victim-only secret readable via document.cookie for the app origin.
        try:
            d.add_cookie({"name": "session", "value": FLAG})
        except Exception:
            # If not yet on the app origin, land on it first, then set the cookie.
            d.get(base + "/index.php")
            time.sleep(1.0)
            d.add_cookie({"name": "session", "value": FLAG})
        # 3) Visit the attacker's crafted reqURI URL. The reflected <iframe src="javascript:...">
        #    fires on load (no click). A blanked reqURI just loads mainPage.php -> no exfil.
        try:
            d.get(target)
        except Exception:
            pass
        time.sleep(5.0)  # let any javascript:-triggered iframe navigation / callback fire
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
            # Selenium/native crashes must not kill this HTTP process (or /visit
            # returns "Remote end closed connection" and later verifies 20).
            try:
                r = subprocess.run(
                    [sys.executable, __file__, "--once", p["target"][0], p["origin"][0]],
                    timeout=120,
                    capture_output=True,
                )
                body = b"done" if r.returncode == 0 else (
                    b"err: " + (r.stderr or r.stdout or b"visit-fail")[:300]
                )
            except Exception as e:
                body = ("err: " + str(e)).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif q.path == "/health":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--once":
        visit(sys.argv[2], sys.argv[3])
        sys.exit(0)
    http.server.HTTPServer(("0.0.0.0", 8070), H).serve_forever()
