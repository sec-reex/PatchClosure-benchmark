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
    "v0": "http://127.0.0.1:39710",
    "v1": "http://127.0.0.1:39711",
    "v2": "http://127.0.0.1:39712",
}


def _get(url, timeout=25):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, "<get-error: %s>" % (e,)


def run_probe(candidate, *, version="v1"):
    base = BASE.get(version)
    if base is None:
        return {"version": version, "error": "no env for this version", "body": ""}
    frm = candidate.get("from", "") if isinstance(candidate, dict) else str(candidate)
    q = urllib.parse.urlencode({"from": frm})
    status, body = _get("%s/send?%s" % (base, q))
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = {"raw": body}
    canary = ""
    if isinstance(parsed, dict):
        canary = parsed.get("canary_out") or parsed.get("body") or ""
    return {
        "version": version,
        "probe": frm,
        "http_status": status,
        "result": parsed,
        "body": canary if canary else body,
    }


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
