#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys
import urllib.request

BASE = {
    "v0": "http://127.0.0.1:39620",
    "v1": "http://127.0.0.1:39621",
    "v2": "http://127.0.0.1:39622",
}


def run_probe(candidate, *, version="v1"):
    base = BASE.get(version, BASE["v1"])
    cand = candidate if isinstance(candidate, dict) else {}
    hname = cand.get("header_name", "Client-IP")
    hval = cand.get("header_value", "")
    req = urllib.request.Request(
        base + "/",
        headers={hname: hval, "User-Agent": "pcb-nukesentinel-probe"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode("utf-8", "replace")
        return {"version": version, "body": body, "status": 200}
    except Exception as e:
        return {"version": version, "error": repr(e), "body": ""}


_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = "http://127.0.0.1:%s" % int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
