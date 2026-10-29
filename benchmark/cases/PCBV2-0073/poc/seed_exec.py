#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:42080",
    "v1": "http://127.0.0.1:42081",
}
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
BASE = {
    "v0": "http://127.0.0.1:42080",
    "v1": "http://127.0.0.1:42081",
}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    path = candidate.get("path", "/probe") if isinstance(candidate, dict) else "/probe"
    field_name = candidate["field_name"] if isinstance(candidate, dict) else str(candidate)
    field_value = candidate["field_value"] if isinstance(candidate, dict) else X
    url = f"{base}{path}"
    
    args = ["curl", "-sS", "-m", "20", "-X", "POST", "-F", f"{field_name}={field_value}", url]
    proc = subprocess.run(args, text=True, capture_output=True, check=False)
    out = proc.stdout.strip()
    try:
        data = json.loads(out)
    except Exception:
        data = {"raw": out, "stderr": proc.stderr[-400:]}
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "object_prototype_polluted": data.get("object_prototype_polluted"),
        "canary_value": data.get("canary_value"),
        "inner_http_status": data.get("inner_http_status"),
    }


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