#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39630",
    "v1": "http://127.0.0.1:39631",
}
import argparse
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
LOGIN_PWD = "admin"
LOGIN_USR = "Administrator"
SITE_HOST = {
    "v0": "v0.local",
    "v1": "v1.local",
}
BASE = {
    "v0": "http://127.0.0.1:39630",
    "v1": "http://127.0.0.1:39631",
}
DOCTYPE = "User"
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    host = SITE_HOST[version]
    order_by = candidate.get("order_by", "name")

    opener = _make_opener(host)
    if not _login(opener, base):
        return {
            "version": version,
            "order_by": order_by,
            "http_status": None,
            "response": "<login-failed>",
        }

    url = (
        f"{base}/api/resource/{DOCTYPE}"
        f"?order_by={urllib.parse.quote(order_by, safe='')}"
        f"&limit_page_length=1"
    )
    status, resp = _get(opener, url)
    return {
        "version": version,
        "order_by": order_by,
        "http_status": status,
        "response": resp,
    }
def _make_opener(host: str):
    
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        _HostHeaderHandler(host),
    )
    return opener
def _login(opener, base: str, timeout: int = 15) -> bool:
    
    data = urllib.parse.urlencode({"usr": LOGIN_USR, "pwd": LOGIN_PWD}).encode()
    try:
        req = urllib.request.Request(f"{base}/api/method/login", data=data)
        resp = opener.open(req, timeout=timeout)
        return resp.getcode() == 200
    except Exception:  
        return False
def _get(opener, url: str, timeout: int = 25):
    
    try:
        req = urllib.request.Request(url)
        with opener.open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<get-error: {e}>"


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