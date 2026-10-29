#!/usr/bin/env python3
"""HTTP-based executable probe for Spring UriComponentsBuilder host-parsing case.
Usage: python3 seed_exec.py <candidate.json> [version]
Hits the HTTP gateway at POST /probe with {url}.
"""
import json
import os
import sys
import urllib.request

HOST = os.environ.get("PCB_HOST", "127.0.0.1")
_PORT_ENV = os.environ.get("PCB_PORT") or os.environ.get("PCB_TARGET_PORT")
PORTS = {"v0": 39515, "v1": 39516, "v2": 39517}
X = os.environ.get("PCB_X") or os.environ.get("PCB_FLAG") or os.environ.get("RUN_FLAG") or "PCBFLAG_UNSET"


def run_probe(candidate, *, version="v1"):
    port = int(_PORT_ENV) if _PORT_ENV else PORTS[version]
    spec = {"url": candidate["url"]} if isinstance(candidate, dict) else {"url": candidate}
    body = json.dumps(spec).encode()
    url = f"http://{HOST}:{port}/probe"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode())
    except Exception as e:
        raise RuntimeError(f"gateway request failed: {e}")
    resp_body = result.get("body", "") if isinstance(result, dict) else ""
    flag_hit = X if X and X != "PCBFLAG_UNSET" and X in str(resp_body) else ""
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "spring_host": result.get("spring_host", ""),
        "guard_pass": result.get("guard_pass"),
        "nav_host": result.get("nav_host", ""),
        "body": resp_body,
        "X": flag_hit,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
