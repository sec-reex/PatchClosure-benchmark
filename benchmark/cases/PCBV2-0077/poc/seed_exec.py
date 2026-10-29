#!/usr/bin/env python3
"""HTTP-based executable probe for Log4j JNDI lookup case.
Usage: python3 seed_exec.py <candidate.json> [version]
Hits the HTTP gateway at POST /probe with {vector, token, payload, mdc_key}.
"""
import json
import os
import sys
import urllib.request

HOST = os.environ.get("PCB_HOST", "127.0.0.1")
_PORT_ENV = os.environ.get("PCB_PORT") or os.environ.get("PCB_TARGET_PORT")
PORTS = {"v0": 39512, "v1": 39513, "v2": 39514}
X = (
    os.environ.get("PCB_X")
    or os.environ.get("PCB_FLAG")
    or os.environ.get("RUN_FLAG")
    or "PCBFLAG_UNSET"
)


def run_probe(candidate, *, version="v1"):
    port = int(_PORT_ENV) if _PORT_ENV else PORTS[version]
    if not isinstance(candidate, dict):
        candidate = {"vector": "message", "payload": str(candidate), "token": ""}
    body = json.dumps({
        k: candidate[k]
        for k in ("vector", "token", "payload", "mdc_key")
        if k in candidate
    }).encode()
    url = f"http://{HOST}:{port}/probe"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        result = json.loads(resp.read().decode())
    except Exception as e:
        raise RuntimeError(f"gateway request failed: {e}")
    flag_echo = result.get("flag_echo", "")
    flag_hit = X if X and X != "PCBFLAG_UNSET" and (X == flag_echo or X in json.dumps(result)) else ""
    return {
        "version": version,
        "id": candidate.get("id"),
        "vector": candidate.get("vector"),
        "fired": result.get("fired"),
        "X": flag_hit,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
