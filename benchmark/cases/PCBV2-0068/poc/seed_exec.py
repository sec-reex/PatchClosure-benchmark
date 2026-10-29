#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
PORT = {"v0": 18318, "v1": 18319}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    if isinstance(candidate, dict):
        condition = candidate.get("condition", "")
        params = candidate.get("params", {}) or {}
        cid = candidate.get("id")
    else:
        condition, params, cid = str(candidate), {}, None
    try:
        _status, body = _http_post(version, "/eval", {"condition": condition, "params": params})
    except Exception as e:
        body = f'{{"error":"http failed: {e}"}}'
    try:
        status = json.loads(body)
    except Exception:
        status = {}
    flag_hit = X if X in body else ""
    return {
        "version": version,
        "id": cid,
        "guard_present": status.get("guard_present"),
        "blocked": status.get("blocked"),
        "evaluated": status.get("evaluated"),
        "block_msg": status.get("block_msg", ""),
        "stdout": status.get("stdout", ""),
        "X": flag_hit,
    }
def _http_post(version, path, payload, timeout=20):
    url = f"http://127.0.0.1:{PORT[version]}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


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
    for _d in ("HOSTPORT", "PORTS", "PORT"):
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