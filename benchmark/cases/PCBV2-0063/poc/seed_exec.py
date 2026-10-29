#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39473",
    "v1": "http://127.0.0.1:39474",
}
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
BASE = {
    "v0": "http://127.0.0.1:39473",
    "v1": "http://127.0.0.1:39474",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    if isinstance(candidate, dict):
        params = {}
        if "item_field" in candidate:
            params["item_field"] = candidate["item_field"]
        if "m_field" in candidate:
            params["m_field"] = candidate["m_field"]
        if "m_operation" in candidate:
            params["m_operation"] = candidate["m_operation"]
        if "m_operator" in candidate:
            params["m_operator"] = candidate["m_operator"]
        if "m_pattern" in candidate:
            params["m_pattern"] = candidate["m_pattern"]
    else:
        params = {"item_field": str(candidate)}

    params["action"] = "run"
    url = f"{base}/pcb_probe.php?{urllib.parse.urlencode(params)}"
    status, body = _get(url)
    return {"version": version, "endpoint": "/pcb_probe.php?action=run", "status": status, "body": body}
def _get(url: str, timeout: int = 30):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<get-error: {e}>"


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