#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys

from poc_common import run_payload

BASE = {"v0": "http://127.0.0.1:1", "v1": "http://127.0.0.1:2"}


def run_probe(candidate, *, version="v1"):
    if isinstance(candidate, dict):
        payload = candidate.get("payload", "")
        san_mode = candidate.get("san_mode", "tags")
        visit_mode = candidate.get("mode", "load")
    else:
        payload, san_mode, visit_mode = str(candidate), "tags", "load"
    dump = run_payload(payload, version, san_mode=san_mode, visit_mode=visit_mode)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "san_mode": san_mode,
        "body": dump,
        "dump": dump,
    }


_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
