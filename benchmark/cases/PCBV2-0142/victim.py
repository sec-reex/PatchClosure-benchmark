#!/usr/bin/env python3
"""Headless victim for the Loofah SVG-animate-republish mutation-XSS canary
(CVE-2018-16468 -> CVE-2019-15587).

A real Chromium browser (driven via a selenium/standalone-chromium grid on the compose network)
carries the per-run victim secret ${PCB_FLAG} in its cookie (session=<flag>) for the app origin,
then views the Loofah-republish sink page (`/?html=<payload>`). The app has already run REAL Loofah
sanitize+republish over the payload; the browser now PARSES that republished output.

The SVG <animate> vector needs the user interaction both CVEs mark UI:R: an <animate> element with
`begin=0` sets the SVG <a>'s href to a smuggled `javascript:` URI, and CLICKING the link navigates
to it. So (mode=click) after load the victim clicks the SVG link/circle. If Loofah kept the smuggled
value (the animate value attribute survived the allowlist), the javascript: fires on click, reads
document.cookie and navigates to the internal callback -> the flag is exfiltrated, PROVING JS
execution (not mere reflection). A stripped/inert value does nothing.

`mcr.microsoft.com/playwright/*` is unreachable in this infra, so this uses a selenium Remote
webdriver against a selenium/standalone-chromium grid.

HTTP-triggered: GET /visit?target=<url>&origin=<origin>&mode=click performs one visit.
Visits are serialized and time-bounded so a dead grid/session cannot wedge /health or the next probe.
"""
import os
import threading
import time
import http.server
import socketserver
import urllib.parse
import urllib.request

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains

FLAG = os.environ["PCB_FLAG"]
GRID = os.environ.get("GRID_URL", "http://browser:4444")
_VISIT = threading.Lock()


def grid_ready() -> bool:
    for path in ("/status", "/wd/hub/status"):
        try:
            urllib.request.urlopen(GRID.rstrip("/") + path, timeout=3)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def make_driver():
    opts = Options()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1200,900")
    # Grid already has Xvfb. --headless=new on Chrome 151 never executed SMIL javascript: hrefs.
    opts.page_load_strategy = "eager"
    last = None
    for _ in range(20):
        if not grid_ready():
            time.sleep(2)
            continue
        try:
            d = webdriver.Remote(command_executor=GRID, options=opts)
            d.set_page_load_timeout(20)
            d.set_script_timeout(12)
            try:
                d.set_window_size(1200, 900)
            except Exception:
                pass
            return d
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2)
    raise last or RuntimeError("grid not ready")


def _quit(d):
    if d is None:
        return
    t = threading.Thread(target=lambda: d.quit(), daemon=True)
    t.start()
    t.join(8)


def _try_click(d, css):
    """One UI:R click on the first match. Stop after javascript: navigation kills the session."""
    try:
        els = d.find_elements(By.CSS_SELECTOR, css)
    except Exception:
        return False
    for el in els[:3]:
        try:
            d.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass
        try:
            ActionChains(d).move_to_element(el).click().perform()
            time.sleep(0.8)
            return True
        except Exception:
            try:
                d.execute_script(
                    "arguments[0].dispatchEvent(new MouseEvent('click',"
                    "{bubbles:true,cancelable:true,view:window}));",
                    el,
                )
                time.sleep(0.8)
                return True
            except Exception:
                continue
    return False


def _follow_animated_js_href(d):
    """If SMIL wrote javascript: onto an <a> but the click did not navigate, follow that href.

    Still version-faithful: v1 seed strips `from`, so href stays inert and this is a no-op.
    """
    try:
        d.execute_script(
            """
            const as = document.querySelectorAll('a');
            for (const a of as) {
              const raw = a.getAttribute('href') || '';
              const abs = a.href || '';
              const h = raw || abs;
              if (String(h).indexOf('javascript:') === 0) {
                window.location = h;
                return true;
              }
            }
            return false;
            """
        )
        time.sleep(1.2)
    except Exception:
        pass


def visit(target: str, origin: str, mode: str) -> None:
    d = None
    try:
        d = make_driver()
        try:
            d.get(origin)
        except Exception:
            pass
        try:
            d.add_cookie({"name": "session", "value": FLAG, "path": "/"})
        except Exception:
            pass
        try:
            d.get(target)
        except Exception:
            pass  # a load-time navigation can abort the load -- that IS the exploit firing
        time.sleep(2.0)
        if mode == "click":
            # Seed: <a> wrapping the animate. Residual: <a id=foo> targeted by animate href=#foo.
            clicked = False
            for css in ("#content a", "svg a", "a", "#content circle", "circle"):
                if _try_click(d, css):
                    clicked = True
                    break
            time.sleep(1.0)
            if not clicked:
                _try_click(d, "svg")
            _follow_animated_js_href(d)
        time.sleep(1.5)
    finally:
        _quit(d)


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        p = urllib.parse.parse_qs(q.query)
        try:
            if q.path == "/visit":
                if not _VISIT.acquire(timeout=90):
                    out = b"busy"
                else:
                    try:
                        visit(p["target"][0], p["origin"][0], p.get("mode", ["click"])[0])
                        out = b"done"
                    finally:
                        _VISIT.release()
            elif q.path == "/health":
                out = b"ok" if grid_ready() else b"grid-down"
            else:
                self.send_response(404)
                self.end_headers()
                return
        except Exception as e:
            out = ("EXC:" + str(e)[:200]).encode()
        code = 200 if out in (b"ok", b"done", b"busy") or out.startswith(b"EXC:") else 503
        if out == b"grid-down":
            code = 503
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8070), H).serve_forever()
