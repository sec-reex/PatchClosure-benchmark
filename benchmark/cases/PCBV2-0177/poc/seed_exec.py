#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39871",
    "v1": "http://127.0.0.1:39872",
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
    "v0": "http://127.0.0.1:39871",
    "v1": "http://127.0.0.1:39872",
}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    path = candidate["path"] if isinstance(candidate, dict) else candidate
    value = candidate.get("value", True) if isinstance(candidate, dict) else True
    # Do not compose-restart: under a busy daemon, restart races readiness and
    # turns a live service into environment_failure. Fresh start is already clean;
    # v1 seed is blocked so residual does not need a process recycle.
    if not _wait_ready(version):
        _up(version)
        if not _wait_ready(version):
            raise SystemExit(f"service {version} not ready")
    merge_body, merge_status = _post_merge(version, path, value)
    check_body, check_status = _get_check(version)
    if merge_status == "200" and "PCBFLAG_" not in (check_body or ""):
        time.sleep(0.8)
        check_body, check_status = _get_check(version)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "merge_status": merge_status,
        "merge_body": merge_body,
        "check_status": check_status,
        "check_body": check_body,  
        # flag channel for the auto-adapted judge: /check response text carries the
        # planted flag iff Object.prototype was polluted
        "resp": check_body or "",
    }
def _compose(extra):
    env = {**os.environ, "PCB_X": X}
    args = ["docker", "compose"]
    proj = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if proj:
        args += ["-p", proj, "--project-directory", str(HERE.parent)]
    args += extra
    return subprocess.run(args, cwd=str(HERE.parent), text=True, capture_output=True, check=False, env=env)


def _up(version):
    _compose(["--profile", version, "up", "-d", SVC[version]])
def _get_check(version):
    
    url = f"{BASE[version]}/check"
    body, status = _curl(["curl", "-sS", "-m", "10", "-w", "HTTPSTATUS:%{http_code}", url])
    return body, status
def _wait_ready(version, tries=120):
    time.sleep(1.0)
    for _ in range(tries):
        _, status = _get_check(version)
        if status in ("200", "204"):
            return True
        time.sleep(0.5)
    return False
def _post_merge(version, path, value):
    
    url = f"{BASE[version]}/merge"
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