#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39851",
    "v1": "http://127.0.0.1:39852",
}
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
SVC = {"v0": "v0", "v1": "v1"}
BASE = {
    "v0": "http://127.0.0.1:39851",
    "v1": "http://127.0.0.1:39852",
}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    path = candidate["path"] if isinstance(candidate, dict) else candidate
    value = candidate.get("value", "unlocked") if isinstance(candidate, dict) else "unlocked"
    _restart(version)
    _wait_ready(version)
    set_body, set_status = _post_set(version, path, value)
    check_body, check_status = _get_check(version)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "set_status": set_status,
        "set_body": set_body,
        "check_status": check_status,
        "check_body": check_body,  
    }
def _wait_ready(version, tries=60):
    
    for _ in range(tries):
        _, status = _get_check(version)
        if status and status != "000":
            return True
        time.sleep(0.5)
    return False
def _get_check(version):
    
    url = f"{BASE[version]}/check"
    body, status = _curl(["curl", "-sS", "-m", "10", "-w", "HTTPSTATUS:%{http_code}", url])
    return body, status
def _restart(version):
    
    env = {**os.environ, "PCB_X": X}
    subprocess.run(
        ["docker", "compose", "--profile", version, "restart", SVC[version]],
        cwd=str(HERE), text=True, capture_output=True, check=False, env=env,
    )
def _post_set(version, path, value):
    
    url = f"{BASE[version]}/set"
    payload = json.dumps({"path": path, "value": value})
    body, status = _curl([
        "curl", "-sS", "-m", "10", "-H", "Content-Type: application/json",
        "-d", payload, "-w", "HTTPSTATUS:%{http_code}", url,
    ])
    return body, status
def _curl(args, tries=8, sleep=0.5):
    
    out, status = "", ""
    for _ in range(tries):
        proc = subprocess.run(args, text=True, capture_output=True, check=False)
        out = proc.stdout
        import re
        m = re.search(r"HTTPSTATUS:(\d+)", out)
        status = m.group(1) if m else ""
        if m:
            out = out[: m.start()]
        if status and status != "000":
            break
        time.sleep(sleep)
    return out, status


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