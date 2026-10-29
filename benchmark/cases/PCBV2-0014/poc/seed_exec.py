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
import uuid
from pathlib import Path
PORT = {"v0": 18790, "v1": 18791}
SERVICE = {"v0": "v0", "v1": "v1"}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    if not isinstance(candidate, dict):
        candidate = {"id": "?", "sheet_b64": str(candidate)}
    xlsx = _package_xlsx(candidate.get("sheet_b64", ""), version=version)
    resp = _http_upload(xlsx, version=version)
    out = resp["text"]
    flag_hit = X if X in out else ""
    a1 = ""
    for line in out.splitlines():
        if line.startswith("A1="):
            a1 = line[3:]
    return {
        "version": version,
        "id": candidate.get("id"),
        "http_status": resp["status"],
        "result": next((l for l in out.splitlines() if l.startswith("RESULT=")), ""),
        "a1": a1,
        "X": flag_hit,
    }
def _package_xlsx(sheet_b64: str, *, version: str) -> bytes:
    
    svc = SERVICE[version]
    r = _compose("exec", "-T", svc, "php", "/app/build_fixture.php",
                 stdin=sheet_b64 + "\n", env={"PCB_X": X})
    out = (r.stdout or "").strip()
    import base64
    try:
        return base64.b64decode(out)
    except Exception:
        return b""
def _http_upload(xlsx: bytes, *, version: str) -> dict:
    
    url = f"http://127.0.0.1:{PORT[version]}/upload"
    boundary = "----pcb" + uuid.uuid4().hex
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="file"; filename="payload.xlsx"\r\n',
        b"Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n",
        xlsx, b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return {"status": resp.status, "text": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "text": e.read().decode("utf-8", "replace")}
    except Exception as e:
        return {"status": -1, "text": f"HTTP-ERROR: {e}"}
def _compose(*args, env=None, stdin=None, capture=True):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        input=stdin, capture_output=capture, check=False,
        env={**os.environ, **(env or {})},
    )


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
    for _d in ("HOSTPORT", "PORTS", "PORT"):
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