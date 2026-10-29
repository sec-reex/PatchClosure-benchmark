#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:43201",
    "v1": "http://127.0.0.1:43202",
}
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
import requests
BASE = {
    "v0": "http://127.0.0.1:43201",
    "v1": "http://127.0.0.1:43202",
}
DATABASE_ID = int(os.environ.get("ANALYTICS_DB_ID", "1"))
LOWPRIV_PASS = os.environ.get("LOWPRIV_PASS", "analyst-pw")
LOWPRIV_USER = os.environ.get("LOWPRIV_USER", "analyst")
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    sql = candidate["sql"] if isinstance(candidate, dict) else str(candidate)
    
    
    last = {"status": 0, "body": ""}
    for _ in range(6):
        last = _http_execute(base, sql)
        if last["status"] not in (0,):
            break
        time.sleep(1.0)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "status": last["status"],
        "body": last["body"],
    }
def _http_execute(base: str, sql: str) -> dict:
    
    s = requests.Session()
    try:
        r = s.post(f"{base}/api/v1/security/login",
                   json={"username": LOWPRIV_USER, "password": LOWPRIV_PASS,
                         "provider": "db", "refresh": True}, timeout=30)
        if r.status_code != 200:
            return {"status": r.status_code, "body": f"login-failed: {r.text[:300]}"}
        tok = r.json().get("access_token")
        h = {"Authorization": f"Bearer {tok}"}
        rc = s.get(f"{base}/api/v1/security/csrf_token/", headers=h, timeout=30)
        csrf = rc.json().get("result") if rc.status_code == 200 else None
        h2 = dict(h)
        if csrf:
            h2["X-CSRFToken"] = csrf
        h2["Referer"] = base
        
        
        payload = {"database_id": DATABASE_ID, "sql": sql, "runAsync": False,
                   "schema": "public", "json": True, "client_id": uuid.uuid4().hex[:20]}
        re = s.post(f"{base}/api/v1/sqllab/execute/", headers=h2, json=payload, timeout=90)
        return {"status": re.status_code, "body": re.text}
    except Exception as e:  
        return {"status": 0, "body": f"transport-error: {e!r}"}


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