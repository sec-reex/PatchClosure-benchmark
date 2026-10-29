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
import urllib.parse
import urllib.request
from pathlib import Path
BASE = {
    "v0": "http://127.0.0.1:38080/",
    "v1": "http://127.0.0.1:38081/",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE.get(version)
    if base is None:
        return {"version": version, "error": "no env for this version"}
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    body = _http_post(base, {"path": url})
    result = {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "url": url,
        "surfaced": body.get("surfaced", "") if isinstance(body, dict) else "",
        "error": body.get("error", "") if isinstance(body, dict) else "",
    }
    if "_http_error" in body:
        result["error"] = body["_http_error"]
    result["http_response"] = body
    # flag channel for the auto-adapted judge: raw server response text (contains the
    # planted flag when the phar wrapper reached the loader)
    result["resp"] = json.dumps(body, ensure_ascii=False) if isinstance(body, dict) else str(body)
    return result
def _http_post(url: str, fields: dict, timeout: float = 15.0) -> dict:
    
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception as e:  
        return {"_http_error": f"{type(e).__name__}: {e}"}
    try:
        return json.loads(body)
    except Exception:  
        return {"_raw": body}


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