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
    "v0": ("127.0.0.1", 39733),
    "v1": ("127.0.0.1", 39734)}

def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    addr = ADDR.get(version)
    if addr is None:
        return {"version": version, "error": "no env for this version", "X": ""}
    raw_req = candidate["raw"] if isinstance(candidate, dict) else bytes(candidate)
    if isinstance(raw_req, str):
        raw_req = raw_req.encode("latin-1")
    marker = candidate["marker"] if isinstance(candidate, dict) else b""
    if isinstance(marker, str):
        marker = marker.encode("latin-1")
    resp = _send_raw(addr, raw_req)
    split = _confirm_split(resp, marker)
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "mode": candidate.get("mode") if isinstance(candidate, dict) else None,
        "split_confirmed": split,
        "response_head": resp[:400].decode("latin-1"),  
        "X": X if split else "",
    }
def _confirm_split(raw: bytes, marker: bytes) -> bool:
    
    end = raw.find(b"\r\n\r\n")
    block = raw[:end] if end >= 0 else raw
    for line in block.split(b"\r\n")[1:]:  
        name = line.split(b":", 1)[0].strip().lower()
        if name == b"x-split" and marker in line:
            return True
    return False
def _send_raw(addr, raw: bytes, timeout: float = 6.0) -> bytes:
    
    host, port = addr
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return ("<connect-error: %s>" % e).encode("latin-1")
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
    return buf


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
    for _d in ("HOSTPORT", "PORTS", "ADDR"):
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