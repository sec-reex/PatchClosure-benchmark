#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    ("v0", "local"): "http://127.0.0.1:39670",
    ("v1", "local"): "http://127.0.0.1:39671",
    ("v1", "s3"): "http://127.0.0.1:39672",
}
import argparse
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
DL_PATH = "/admin/media/download_private_file"
LOGIN_PASS = os.environ.get("PCB_PASS", "AdminPass123!")
LOGIN_USER = os.environ.get("PCB_USER", "admin")
BASE = {
    ("v0", "local"): "http://127.0.0.1:39670",
    ("v1", "local"): "http://127.0.0.1:39671",
    ("v1", "s3"): "http://127.0.0.1:39672",
}
def run_probe(candidate, *, version="v1"):
    
    backend = candidate.get("backend", "local") if isinstance(candidate, dict) else "local"
    payload = candidate.get("payload") if isinstance(candidate, dict) else str(candidate)
    base = BASE.get((version, backend))
    if not base:
        return {"version": version, "backend": backend, "error": f"no env for ({version},{backend})"}

    op = _opener()
    logged_in = _login(op, base)
    url = base + DL_PATH + "?" + urllib.parse.urlencode({candidate.get("param", "file"): payload})
    status, body, _ = _get(op, url)
    return {
        "version": version,
        "backend": backend,
        "logged_in": logged_in,
        "request": url,
        "http_status": status,
        "body": (body or "")[:2000],
    }
def _opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def _get(op, url, timeout=30):
    try:
        with op.open(urllib.request.Request(url), timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), url
    except Exception as e:  
        return None, f"<http-error: {e}>", url
def _login(op, base):
    status, html, _ = _get(op, base + "/admin/login")
    m = re.search(r'name="authenticity_token"[^>]*value="([^"]+)"', html or "") or \
        re.search(r'name="csrf-token"[^>]*content="([^"]+)"', html or "")
    tok = m.group(1) if m else ""
    st, _, final = _post(op, base + "/admin/login",
                         {"authenticity_token": tok,
                          "user[username]": LOGIN_USER, "user[password]": LOGIN_PASS})
    return "/admin/login" not in (final or "") or "dashboard" in (final or "").lower()
def _post(op, url, data: dict, timeout=30):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), url
    except Exception as e:  
        return None, f"<http-error: {e}>", url


import os as _os_pcb
_pbt = _os_pcb.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = _os_pcb.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            _val = globals()["BASE"][_v]
            if isinstance(_val, (tuple, list)):
                globals()["BASE"][_v] = (str(_val[0]), int(_pt))
            elif isinstance(_val, int) or (isinstance(_val, str) and _val.isdigit()):
                globals()["BASE"][_v] = int(_pt)
            else:
                globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"
    for _d in ("HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))