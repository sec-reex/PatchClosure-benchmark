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
from pathlib import Path
CLIENT_CMD = 'java -cp "$(cat /work/cp.txt)" Client'
SERVER_PORT = "9009"
SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent.parent  # case dir (compose file)
def run_probe(candidate, *, version="v1"):
    
    svc = SERVICE[version]
    if not isinstance(candidate, dict):
        candidate = {"mode": str(candidate)}
    mode = candidate.get("mode", "type1")
    
    out = ""
    for attempt in range(3):
        r = _compose(
            "--profile", "client", "--profile", version,
            "run", "--rm", "--no-deps", "client",
            "sh", "-c", f"{CLIENT_CMD} {svc} {SERVER_PORT} {mode}",
            env={"PCB_X": X}, timeout=120,
        )
        out = (r.stdout or "") + (r.stderr or "")
        if X in out or "CLIENT_RESP=" in out:
            break
        time.sleep(1.0)
    if "CLIENT_RESP=" not in out and r.returncode != 0:
        raise SystemExit(f"client compose failed rc={r.returncode}: {out[-800:]}")
    flag_hit = X if X in out else ""
    resp = ""
    for line in out.splitlines():
        if line.startswith("CLIENT_RESP="):
            resp = line[len("CLIENT_RESP="):]
            break
    return {
        "version": version,
        "id": candidate.get("id"),
        "mode": mode,
        "resp": resp,
        "X": flag_hit,
        "raw": out[-600:],
    }
def _compose(*args, env=None, stdin=None, timeout=None):
    proj = os.environ.get("COMPOSE_PROJECT_NAME", "")
    cmd = ["docker", "compose"]
    if proj:
        cmd += ["-p", proj]
    cmd += ["--project-directory", str(HERE)]
    cmd += list(args)
    return subprocess.run(
        cmd, cwd=str(HERE), text=True,
        input=stdin, capture_output=True, check=False, timeout=timeout,
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