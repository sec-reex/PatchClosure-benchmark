#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import argparse
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
PORTS = {"v0": 18960, "v1": 18961}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    port = PORTS[version]
    if not isinstance(candidate, dict):
        candidate = {"payload": str(candidate)}
    payload = candidate.get("payload", "")
    dtd = candidate.get("dtd_content")
    if dtd:
        with _DtdServer(dtd):
            body = _http_post_xml(port, payload)
    else:
        body = _http_post_xml(port, payload)
    return {
        "version": version,
        "id": candidate.get("id"),
        "value": body,
        "X": X if X in body else "",
    }
def _http_post_xml(port: int, body: str, timeout: float = 20.0) -> str:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/app/xml", data=body.encode("utf-8"),
        headers={"Content-Type": "application/xml"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:            
        try:
            return e.read().decode("utf-8", "replace")
        except Exception:
            return f"HTTPError {e.code}"
    except Exception as e:
        return f"ERROR {type(e).__name__}: {e}"


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