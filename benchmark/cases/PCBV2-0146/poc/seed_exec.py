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
    "v0": ("127.0.0.1", 39680),
    "v1": ("127.0.0.1", 39681)}

def run_probe(candidate, *, version="v1"):
    
    host, port = HOSTPORT[version]
    if not isinstance(candidate, dict):
        candidate = {"body": str(candidate), "mode": "plain"}
    resp = _send_raw(host, port, _build_request(host, candidate))
    return {
        "version": version,
        "probe_id": candidate.get("probe_id"),
        "mode": candidate.get("mode"),
        "content_length": len(candidate.get("body", "")),
        "response": resp,
    }
def _send_raw(host: str, port: int, raw: bytes, timeout: int = 30) -> str:
    
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(raw)
            chunks = []
            while True:
                try:
                    b = s.recv(65536)
                except socket.timeout:
                    break
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks).decode("utf-8", "replace")
    except Exception as e:  
        return f"<send-error: {e}>"
def _build_request(host: str, candidate: dict) -> bytes:
    
    method = candidate.get("method", "POST")
    endpoint = candidate.get("endpoint", "/v1.45/containers/create")
    ctype = candidate.get("content_type", "application/json")
    mode = candidate.get("mode", "plain")
    body = candidate.get("body", "").encode("utf-8")

    lines = [f"{method} {endpoint} HTTP/1.1", f"Host: {host}",
             f"Content-Type: {ctype}", "Connection: close"]

    if mode == "chunked":
        
        lines.append("Transfer-Encoding: chunked")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode()
        frame = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        return head + frame

    
    
    lines.append(f"Content-Length: {len(body)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode()
    return head + body


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