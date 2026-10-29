#!/usr/bin/env python3
"""HTTP-based executable probe for follow-redirects header-strip case.
Usage: python3 seed_exec.py <candidate.json> [version]
Hits the HTTP gateway at /probe?mode=seed|residual.
"""
import json
import os
import sys
import urllib.request

HOST = os.environ.get("PCB_HOST", "127.0.0.1")
_PORT_ENV = os.environ.get("PCB_PORT") or os.environ.get("PCB_TARGET_PORT")
PORTS = {"v0": 39506, "v1": 39507, "v2": 39508}
FLAG = os.environ.get("PCB_FLAG") or os.environ.get("PCB_X") or ""


def run_probe(candidate, version="v1"):
    port = int(_PORT_ENV) if _PORT_ENV else PORTS[version]
    mode = candidate.get("probe", "seed") if isinstance(candidate, dict) else "seed"
    url = f"http://{HOST}:{port}/probe?mode={mode}"
    try:
        resp = urllib.request.urlopen(url, timeout=30)
        data = json.loads(resp.read().decode())
    except Exception as e:
        return f"ERROR: {e}"
    headers_body = data.get("headers", "")
    label = "SEED_FINAL_HEADERS:" if mode == "seed" else "RESIDUAL_FINAL_HEADERS:"
    return f"{label}{headers_body}"


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
