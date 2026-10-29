#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
BASE = {
    "rewrite":   {"v0": ("127.0.0.1", 38260), "v1": ("127.0.0.1", 38261)},
    "proxypass": {"v0": ("127.0.0.1", 38263), "v1": ("127.0.0.1", 38264)},
}
def run_probe(candidate, *, version="v1"):
    
    route = candidate.get("route", "rewrite") if isinstance(candidate, dict) else "rewrite"
    host, port = _addr(route, version)
    raw = candidate["raw"] if isinstance(candidate, dict) else bytes(candidate)
    if isinstance(raw, str):
        raw = raw.encode()
    resp = _send_raw(host, port, raw)
    text = resp.decode("latin-1", "replace")
    status_line = text.split("\r\n", 1)[0] if text else ""
    return {
        "version": version,
        "route": route,
        "request": raw.decode("latin-1", "replace"),
        "request_target": candidate.get("request_target") if isinstance(candidate, dict) else None,
        "http_version": candidate.get("http_version") if isinstance(candidate, dict) else None,
        "status_line": status_line,
        "response": text[:800],
    }
def _addr(route: str, version: str):
    pt = os.environ.get("PCB_TARGET_PORT")
    entry = BASE.get(route, BASE["rewrite"])
    if isinstance(entry, dict) and version in entry:
        host, port = entry[version]
        return host, (int(pt) if pt and str(pt).isdigit() else port)
    if pt and str(pt).isdigit():
        return "127.0.0.1", int(pt)
    raise KeyError(f"no addr for {route}/{version}")
def _send_raw(host: str, port: int, raw: bytes, timeout: int = 15) -> bytes:
    
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:  
        return f"<connect-error: {e}>".encode()
    try:
        s.sendall(raw)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        s.settimeout(timeout)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)
    except Exception as e:  
        return f"<io-error: {e}>".encode()
    finally:
        s.close()


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