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
import sys
import time
from pathlib import Path
HOSTPORT = {
    "v0": ("127.0.0.1", 39390),
    "v1": ("127.0.0.1", 39391),
}
def run_probe(candidate, *, version="v1"):
    
    host, port = HOSTPORT[version]
    if isinstance(candidate, dict):
        path = candidate.get("path", "/")
        headers = candidate.get("headers", {}) or {}
    else:
        path, headers = str(candidate), {}
    status, body = _raw_get(host, port, path, headers)
    return {
        "version": version,
        "path": path,
        "headers": headers,
        "status": status,
        "body": body,
    }
def _raw_get(host: str, port: int, path: str, headers: dict, timeout: float = 20.0):
    
    hdrs = {"Host": f"{host}:{port}"}
    hdrs.update(headers or {})
    
    if "Connection" not in hdrs and "connection" not in hdrs:
        hdrs["Connection"] = "close"
    lines = [f"GET {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in hdrs.items()]
    req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            chunks = []
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
        raw = b"".join(chunks)
    except Exception as e:  
        return None, f"<socket-error: {e}>"
    head, _, body = raw.partition(b"\r\n\r\n")
    status = None
    first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = first.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return status, body.decode("utf-8", "replace")


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