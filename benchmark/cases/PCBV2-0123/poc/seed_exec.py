#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:47610",
    "v1": "http://127.0.0.1:47611",
}
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
ROUTE_PREFIX = {"v0": "", "v1": ""}
BASE = {
    "v0": "http://127.0.0.1:47610",
    "v1": "http://127.0.0.1:47611",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    path = candidate["path"] if isinstance(candidate, dict) else str(candidate)
    prefix = ROUTE_PREFIX.get(version, "")
    if prefix and path.startswith("/file="):
        path = prefix + path
    proc = subprocess.run(
        ["curl", "--path-as-is", "-sS", "-m", "15", "-w", "\n%{http_code}", f"{base}{path}"],
        text=True, capture_output=True, check=False,
    )
    out = proc.stdout
    status, body = "", out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    return {"version": version, "path": path, "status": status, "body": body}


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