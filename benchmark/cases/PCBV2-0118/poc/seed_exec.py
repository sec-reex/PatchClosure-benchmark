#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:43171",
    "v1": "http://127.0.0.1:43172",
}
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote
_STATUS_RE = re.compile(r"HTTPSTATUS:(\d+)")
_CSRF_RE2 = re.compile(r'value="([^"]*)"\s+name="_csrf"')
_CSRF_RE = re.compile(r'name="_csrf"\s+value="([^"]*)"')
_LOCATION_RE = re.compile(r"^location:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
SEED_PASS = "pcbpassword123"
SEED_USER = "pcbuser"
BASE = {
    "v0": "http://127.0.0.1:43171",
    "v1": "http://127.0.0.1:43172",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    path = candidate["path"] if isinstance(candidate, dict) else "/user/login"
    nxt = candidate["redirect_to"] if isinstance(candidate, dict) else str(candidate)
    enc = quote(nxt, safe="")
    get_url = f"{base}{path}?redirect_to={enc}"
    post_url = f"{base}/user/login"

    status, location = "", ""
    for _attempt in range(6):
        with tempfile.TemporaryDirectory() as td:
            jar = os.path.join(td, "jar")
            
            g = subprocess.run(
                ["curl", "-sS", "-m", "15", "-c", jar, get_url],
                text=True, capture_output=True, check=False,
            )
            if not g.stdout:
                time.sleep(0.5)
                continue
            
            
            
            csrf = _csrf_from_html(g.stdout)
            post_args = ["curl", "-sS", "-m", "15", "-b", jar, "-c", jar, "-D", "-", "-o", "/dev/null",
                         "-w", "HTTPSTATUS:%{http_code}",
                         "--data-urlencode", f"user_name={SEED_USER}",
                         "--data-urlencode", f"password={SEED_PASS}"]
            if csrf:
                post_args += ["--data-urlencode", f"_csrf={csrf}"]
            post_args.append(post_url)
            
            p = subprocess.run(post_args, text=True, capture_output=True, check=False)
            out = p.stdout
            sm = _STATUS_RE.search(out)
            status = sm.group(1) if sm else ""
            if sm:
                out = out[: sm.start()]
            lm = _LOCATION_RE.search(out)
            location = lm.group(1).strip() if lm else ""
            if status and status != "000":
                break
        time.sleep(0.5)

    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "status": status,
        "location": location,
    }
def _csrf_from_html(html: str) -> str:
    m = _CSRF_RE.search(html) or _CSRF_RE2.search(html)
    return m.group(1) if m else ""


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