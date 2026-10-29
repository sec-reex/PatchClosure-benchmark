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
import urllib.parse
from pathlib import Path
PORTS = {
    "v0": {"app": 39780, "hits": 39781},
    "v1": {"app": 39782, "hits": 39783}, "hits": 39785}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    p = PORTS.get(version)
    if p is None:
        return {"version": version, "error": "no env for this version"}
    if not isinstance(candidate, dict):
        candidate = {"mode": "seed", "endpoint": "/fetch", "hdr": str(candidate)}
    nonce = candidate.get("nonce") or ("n" + os.urandom(4).hex())
    endpoint = candidate.get("endpoint", "/fetch")
    hdr = candidate.get("hdr", "").format(nonce=nonce)
    app_base = f"http://127.0.0.1:{p['app']}"
    hits_base = f"http://127.0.0.1:{p['hits']}"
    
    _http_get(f"{hits_base}/reset")
    
    q = urllib.parse.urlencode({"nonce": nonce})
    app_resp = _http_post(f"{app_base}{endpoint}?{q}", hdr.encode("latin-1"))
    
    hits = ""
    for _ in range(12):
        hits = _http_get(f"{hits_base}/hits")
        if X in hits:
            break
        time.sleep(0.3)
    return {
        "version": version,
        "id": candidate.get("id"),
        "mode": candidate.get("mode"),
        "nonce": nonce,
        "app_response": app_resp.strip()[:200],
        "X": X if X in hits else "",
    }
def _http_get(url: str, timeout: float = 6.0) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode("latin-1", "replace")
    except Exception as e:  
        return f"<http-error: {e}>"
def _http_post(url: str, body: bytes, timeout: float = 6.0) -> str:
    
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("latin-1", "replace")
    except Exception as e:  
        return f"<http-error: {e}>"


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
    for _d in ("HOSTPORT",):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)
    if "PORTS" in globals() and isinstance(globals()["PORTS"], dict):
        for _v in list(globals()["PORTS"]):
            _inner = globals()["PORTS"][_v]
            if isinstance(_inner, dict):
                _inner["app"] = int(_pt)
                _sc = _os_pcb.environ.get("PCB_SIDECAR_PORT")
                if _sc and str(_sc).isdigit():
                    _inner["hits"] = int(_sc)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))