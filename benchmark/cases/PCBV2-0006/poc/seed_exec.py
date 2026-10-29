#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import argparse
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
CLIENT_SVC = {"v0": "client-v0", "v1": "client-v1"}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    svc = CLIENT_SVC.get(version)
    if svc is None:
        return {"version": version, "error": "no env for this version"}
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    b64 = base64.b64encode(url.encode("latin-1")).decode("ascii")
    r = _compose("exec", "-T", svc, "python", "/client.py", b64, env={"PCB_X": X}, timeout=60)
    out = (r.stdout or "") + (r.stderr or "")
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "url": url,
        "flag_seen": X in out,
        "client_output": out.strip()[:600],
        
        "X": X if X in out else "",
    }
def _compose(*args, env=None, timeout=600):
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(HERE),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


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