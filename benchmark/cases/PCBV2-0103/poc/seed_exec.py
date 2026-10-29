#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:43101",
    "v1": "http://127.0.0.1:43102",
}
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote
_LOCATION_RE = re.compile(r"^location:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
BASE = {
    "v0": "http://127.0.0.1:43101",
    "v1": "http://127.0.0.1:43102",
}
APP_HOST = os.environ.get("APP_HOST", "app.local")
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    path = candidate["path"] if isinstance(candidate, dict) else "/login"
    nxt = candidate["next"] if isinstance(candidate, dict) else str(candidate)
    enc = quote(nxt, safe="")
    url = f"{base}{path}?next={enc}"
    args = ["curl", "-sS", "-m", "10", "-H", f"Host: {APP_HOST}", "-D", "-", "-o", "/dev/null",
            "-w", "HTTPSTATUS:%{http_code}", url]
    
    
    
    out, status = "", ""
    for _attempt in range(6):
        proc = subprocess.run(args, text=True, capture_output=True, check=False)
        out = proc.stdout
        m = re.search(r"HTTPSTATUS:(\d+)", out)
        status = m.group(1) if m else ""
        if m:
            out = out[: m.start()]
        if status and status != "000":
            break
        time.sleep(0.5)
    loc_m = _LOCATION_RE.search(out)
    location = loc_m.group(1).strip() if loc_m else ""
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "status": status,
        "location": location,
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
    # 连接失败（服务未就绪/端口错）＝环境失败（20），区别于 10=效果未发生
    if not r.get("status") or r.get("status") == "000":
        sys.exit(2)