#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
HOSTS = {"v0": ("127.0.0.1", 39810), "v1": ("127.0.0.1", 39811)}
BASE = {k: f"http://{h}:{p}" for k, (h, p) in HOSTS.items()}
def new_flag():
    return os.environ.get("PCB_FLAG") or os.environ.get("RUN_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    host, port = HOSTS[version]
    name = candidate["cookie_name"] if isinstance(candidate, dict) else str(candidate)
    resp = send_raw_cookie(host, port, name, X)
    body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else resp
    return {"version": version, "cookie_name": name, "status_line": resp.split("\r\n", 1)[0],
            "body": body}
def send_raw_cookie(host, port, cookie_name, cookie_value, timeout=10):
    
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: {cookie_name}={cookie_value}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks).decode("latin-1", "replace")


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
    for _d in ("HOSTPORT", "PORTS", "HOSTS"):
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