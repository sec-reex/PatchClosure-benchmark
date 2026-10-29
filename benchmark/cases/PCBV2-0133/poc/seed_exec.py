#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:40080",
    "v1": "http://127.0.0.1:40081",
}
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
CLIENT = "poc"
REALM = "pcb"
BASE = {
    "v0": "http://127.0.0.1:40080",
    "v1": "http://127.0.0.1:40081",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    redirect_uri = candidate["redirect_uri"] if isinstance(candidate, dict) else str(candidate)
    url = _auth_url(base, redirect_uri)
    proc = subprocess.run(
        ["curl", "-L", "--max-redirs", "5", "-sS", "-m", "25",
         "-w", "\n%{http_code} %{url_effective}", url],
        text=True, capture_output=True, check=False,
    )
    out = proc.stdout
    meta = ""
    body = out
    if "\n" in out:
        body, meta = out.rsplit("\n", 1)
    status, _, eff = meta.partition(" ")
    return {"version": version, "redirect_uri": redirect_uri,
            "status": status, "effective_url": eff, "body": body}
def _auth_url(base: str, redirect_uri: str) -> str:
    q = urllib.parse.urlencode({
        "client_id": CLIENT,
        "response_type": "code",
        "scope": "openid",
        "prompt": "none",             
        "state": "pcb",
        "redirect_uri": redirect_uri, 
    })
    return f"{base}/realms/{REALM}/protocol/openid-connect/auth?{q}"


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