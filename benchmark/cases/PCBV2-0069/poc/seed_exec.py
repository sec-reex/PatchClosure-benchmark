#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:42430",
    "v1": "http://127.0.0.1:42431",
}
import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
BASE = {
    "v0": "http://127.0.0.1:42430",
    "v1": "http://127.0.0.1:42431",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    path = candidate.get("path", "/extract")
    tar_bytes = base64.b64decode(candidate["tar_b64"])
    poison = candidate.get("poison")
    url = f"{base}{path}"
    with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tf:
        tf.write(tar_bytes)
        tar_file = tf.name
    try:
        args = ["curl", "-sS", "-m", "20", "-X", "POST",
                "-H", "content-type: application/x-tar"]
        if poison:
            args += ["-H", f"x-pcb-poison: {poison}"]
        args += ["--data-binary", f"@{tar_file}", url]
        proc = subprocess.run(args, text=True, capture_output=True, check=False)
    finally:
        try:
            os.unlink(tar_file)
        except OSError:
            pass
    out = proc.stdout.strip()
    try:
        data = json.loads(out)
    except Exception:
        data = {"raw": out, "stderr": proc.stderr[-400:]}
    return {
        "version": version,
        "probe_id": candidate.get("probe_id"),
        "escaped": data.get("escaped"),
        "escaped_path": data.get("escaped_path"),
        "canary_value": data.get("canary_value"),
        "extract_error": data.get("extract_error"),
    }


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