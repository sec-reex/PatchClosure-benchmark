#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:55110",
    "v1": "http://127.0.0.1:55111",
}
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import os as _os_c
_PROJ = _os_c.environ.get("COMPOSE_PROJECT_NAME", "pcb")
CONTAINER = {
    "v0": f"{_PROJ}-v0-1",
    "v1": f"{_PROJ}-v1-1",
}
BASE = {
    "v0": "http://127.0.0.1:55110",
    "v1": "http://127.0.0.1:55111",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    body = candidate.get("body")
    import urllib.request
    req = urllib.request.Request(base + "/compile", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            http_status = r.status
    except Exception as e:
        http_status = getattr(e, "code", None)
    
    proc = subprocess.run(["docker", "exec", CONTAINER[version], "cat", "/tmp/pwn.txt"],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return {"version": version, "status": http_status, "body": "", "oob": "no-file"}
    return {"version": version, "status": http_status, "body": proc.stdout}


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