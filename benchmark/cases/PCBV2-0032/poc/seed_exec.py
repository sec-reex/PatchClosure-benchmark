#!/usr/bin/env python3
"""HTTP-based executable probe for DBI preparse heap-overflow case.
Usage: python3 seed_exec.py <candidate.json> [version]
Hits the HTTP gateway at GET /probe?n=<N>.
"""
import json
import os
import sys
import urllib.request

HOST = os.environ.get("PCB_HOST", "127.0.0.1")
_PORT_ENV = os.environ.get("PCB_PORT") or os.environ.get("PCB_TARGET_PORT")
PORTS = {"v0": 39503, "v1": 39504, "v2": 39505}
SEED_N = 5000


def run_probe(candidate, version="v1"):
    port = int(_PORT_ENV) if _PORT_ENV else PORTS[version]
    n = candidate.get("n", SEED_N) if isinstance(candidate, dict) else SEED_N
    url = f"http://{HOST}:{port}/probe?n={n}"
    try:
        resp = urllib.request.urlopen(url, timeout=200)
        data = json.loads(resp.read().decode())
    except Exception as e:
        return {"ok": False, "crashed": None, "result": str(e)}
    return {"ok": data.get("crashed", False), "crashed": data["crashed"], "result": data}


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
