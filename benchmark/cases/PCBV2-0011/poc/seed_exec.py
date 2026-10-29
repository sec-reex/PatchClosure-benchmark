#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39480",
    "v1": "http://127.0.0.1:39481",
}
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote
import requests
BASE = {
    "v0": "http://127.0.0.1:39480",
    "v1": "http://127.0.0.1:39481",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    params = _build_params(candidate)
    result = {"version": version, "mode": candidate.get("mode") if isinstance(candidate, dict) else "",
              "params": params}
    try:
        r = requests.get(f"{base}/harness.php", params=params, timeout=25)
        result["http_status"] = r.status_code
        try:
            result["body"] = r.json()
        except Exception:
            result["body"] = {"raw": r.text[:300]}
    except Exception as e:  
        result["error"] = f"{type(e).__name__}: {e}"
    return result
def _build_params(candidate) -> dict:
    
    if not isinstance(candidate, dict):
        return {}
    mode = candidate.get("mode", "")
    params = {"mode": mode}
    if candidate.get("query"):
        
        params.update(candidate["query"])
    if candidate.get("destination_query") is not None:
        dq = candidate["destination_query"]
        inner = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in dq.items())
        path = candidate.get("destination_path", "node")
        params["destination"] = f"{path}?{inner}"
    return params


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