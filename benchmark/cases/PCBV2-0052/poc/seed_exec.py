#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
ADDR = {
    "v0": ("127.0.0.1", 39580),
    "v1": ("127.0.0.1", 39581)}

def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    addr = ADDR.get(version)
    if addr is None:
        return {"version": version, "error": "no env for this version"}
    raw = candidate["raw"] if isinstance(candidate, dict) else bytes(candidate)
    body = _send_raw(addr, raw)
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "flag_seen": X in body,
        "response": body[:400],
        
        "X": X if X in body else "",
    }
def _send_raw(addr, raw: bytes, timeout: float = 6.0) -> str:
    
    host, port = addr
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return f"<connect-error: {e}>"
    s.settimeout(timeout)
    buf = b""
    try:
        s.sendall(raw)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return buf.decode("latin-1")


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