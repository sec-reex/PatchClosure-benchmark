#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys
import urllib.parse
import urllib.request

BASE = {
    "v0": "http://127.0.0.1:40640",
    "v1": "http://127.0.0.1:40641",
    "v2": "http://127.0.0.1:40642",
}


def run_probe(candidate, *, version="v1"):
    base = BASE.get(version, BASE["v1"])
    if isinstance(candidate, dict):
        claim = candidate.get("claim", "raw")
        extent = candidate.get("extent", "/canary/secret.txt")
    else:
        claim, extent = "raw", str(candidate)
    qs = urllib.parse.urlencode({"claim": claim, "extent": extent})
    url = "%s/read?%s" % (base, qs)
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
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
        BASE[_v] = "http://127.0.0.1:%s" % int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
