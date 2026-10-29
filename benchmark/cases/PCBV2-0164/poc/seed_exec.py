#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

APP_ID = "pcbApp"


def _base(_version):
    root = os.environ.get("PCB_TARGET_BASE")
    if root:
        return root.rstrip("/")
    port = os.environ.get("PCB_TARGET_PORT") or "1337"
    return f"http://127.0.0.1:{int(port)}/parse"


def _req(url, *, method="GET", headers=None, body=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"__ERR__ {e}"


def run_probe(candidate, *, version="v1"):
    regex_value = candidate["regex"] if isinstance(candidate, dict) else str(candidate)
    where = json.dumps({"name": {"$regex": regex_value}})
    url = f"{_base(version)}/classes/Vault?where=" + urllib.parse.quote(where)
    code, body = _req(url, headers={"X-Parse-Application-Id": APP_ID})
    return {"version": version, "regex": regex_value, "status": code, "body": body}


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
