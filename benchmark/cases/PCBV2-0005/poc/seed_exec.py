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
import urllib.error
import urllib.request
from pathlib import Path
HOSTPORT = {"v0": 18800, "v1": 18801}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    if not isinstance(candidate, dict):
        candidate = {"type": str(candidate)}
    type_name = str(candidate.get("type", ""))
    xml_body = _xml_for(type_name)
    status, resp = _http_post_deser(version, xml_body)
    flag_hit = X if X in resp else ""
    result_line = ""
    for line in resp.strip().splitlines():
        if line.startswith("RESULT="):
            result_line = line.strip()
    return {
        "version": version,
        "id": candidate.get("id"),
        "probe_type": type_name,
        "http_status": status,
        "harness_result": result_line,
        "X": flag_hit,
        "resp_snip": resp[:200],
    }
def _xml_for(type_name: str) -> str:
    
    element = "" if not type_name else type_name.replace("$", "_-")
    return "<list><" + element + "/><pcb.PcbCanary/></list>"
def _http_post_deser(version, xml_body, timeout=30):
    
    url = f"http://127.0.0.1:{HOSTPORT[version]}/deser"
    body = xml_body.encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "text/xml"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:  
        return -1, f"HTTP_ERROR {type(e).__name__}: {e}"


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