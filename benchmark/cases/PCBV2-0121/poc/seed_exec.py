#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:23400",
    "v1": "http://127.0.0.1:23401",
}
import os
import subprocess
import sys
import time
from pathlib import Path
_tokens = {}
_X_mod = None
_original_mod = None
BASE = {
    "v0": "http://127.0.0.1:23400",
    "v1": "http://127.0.0.1:23401",
}
def run_probe(candidate, *, version="v1"):
    
    _ensure_setup(version)
    
    if isinstance(candidate, dict) and candidate.get("type") == "api_put":
        X = _ensure_X()
        return X.run(version=version, token=_tokens.get(version, ""))
    elif isinstance(candidate, dict) and candidate.get("type") == "web_editor":
        orig = _ensure_original()
        return orig.run(version=version)
    else:
        return "unknown_probe_type"
def _ensure_setup(version: str):
    
    if version not in _tokens:
        
        from gogs_util import setup_version
        _tokens[version] = setup_version(version)
def _ensure_X():
    global _X_mod
    if _X_mod is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent / "X"))
        import X_poc as m
        _X_mod = m
    return _X_mod
def _ensure_original():
    global _original_mod
    if _original_mod is None:
        import original_poc as m
        _original_mod = m
    return _original_mod


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
    if not isinstance(cand, dict) or not cand.get("type"):
        cand = {"type": "web_editor", "probe_id": "cve-2024-56731-upload"}
    r = run_probe(cand, version=version)
    if isinstance(r, str):
        print(json.dumps({"body": r}))
    else:
        print(json.dumps(r, default=str))