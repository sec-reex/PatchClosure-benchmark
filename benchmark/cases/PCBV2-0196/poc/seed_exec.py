#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = {
    "v0": "http://127.0.0.1:39650",
    "v1": "http://127.0.0.1:39651",
}


def _base(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT") or ""
    if port.isdigit():
        return f"http://127.0.0.1:{int(port)}"
    override = os.environ.get("PCB_TARGET_BASE")
    if override:
        return override.rstrip("/")
    return BASE.get(version, BASE["v1"])


def _get(url: str, timeout: float = 10):
    try:
        req = urllib.request.Request(url, method="GET")
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, body
    except Exception as e:
        return str(e), ""


def run_probe(candidate, *, version="v1"):
    base = _base(version)
    params = candidate.get("params", {})
    marker_path = candidate.get("marker_path", "/pcb_original.txt")
    query = urllib.parse.urlencode(params)
    bind_url = f"{base}/hello?{query}"
    bind_status, _ = _get(bind_url, timeout=15)
    for _ in range(3):
        try:
            urllib.request.urlopen(f"{base}/hello?name=flush", timeout=8)
        except Exception:
            pass
    body = ""
    status = ""
    for _ in range(25):
        status, body = _get(f"{base}{marker_path}", timeout=8)
        if status == 200 and "PCBFLAG_" in body:
            break
        time.sleep(1)
    return {"version": version, "bind_status": bind_status, "status": status, "body": body}


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
