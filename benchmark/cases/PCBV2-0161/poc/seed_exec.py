#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys
import urllib.request

BASE = {
    "v0": "http://127.0.0.1:40390",
    "v1": "http://127.0.0.1:40391",
    "v2": "http://127.0.0.1:40392",
}


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    if isinstance(candidate, dict):
        scheme = candidate.get("scheme", "file")
        path = candidate.get("path", "/canary/secret.txt")
    else:
        scheme, path = "file", str(candidate)
    from urllib.parse import urlencode
    qs = urlencode({"scheme": scheme, "path": path})
    url = "%s/read?%s" % (base, qs)
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"version": version, "error": repr(e), "body": ""}


_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = "http://127.0.0.1:%s" % (int(_pt),)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
