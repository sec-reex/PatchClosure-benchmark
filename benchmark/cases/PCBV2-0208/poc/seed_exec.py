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

BASE = {
    "v0": "http://127.0.0.1:39470",
    "v1": "http://127.0.0.1:39471",
    "v2": "http://127.0.0.1:39472",
}


def _request(url, data=None, timeout=25):
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "<err:%s>" % (e,)


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    target = candidate.get("target", "") if isinstance(candidate, dict) else str(candidate)
    mode = candidate.get("mode", "") if isinstance(candidate, dict) else ""
    result = {"version": version, "mode": mode, "target": target, "fetched_body": "", "body": ""}
    payload = urllib.parse.urlencode({"target": target}).encode("utf-8")
    status, body = _request(base + "/harness.php", data=payload)
    result["rename_status"] = status
    try:
        j = json.loads(body)
    except Exception:
        j = {"raw": (body or "")[:200]}
    result["rename"] = j
    url = j.get("url") if isinstance(j, dict) else None
    if url:
        _st, fetched = _request(base + url, data=None)
        result["fetch_status"] = _st
        result["fetched_body"] = (fetched or "")[:200]
        result["body"] = result["fetched_body"]
    return result


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
