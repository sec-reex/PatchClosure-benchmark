#!/usr/bin/env python3
"""Seed executor: run the Velbus XXE original_poc against the live manager."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import original_poc


def _base():
    env = os.environ.get("PCB_TARGET_BASE") or os.environ.get("PCB_BASE")
    if env:
        return env
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return "http://127.0.0.1:%s" % port
    return ""


def run(base=None):
    url = base or _base()
    if not url:
        return {"ok": False, "status": 0, "body": "no manager base"}
    leaked = original_poc.run(url)
    return {"ok": bool(leaked), "status": 200 if leaked else 0, "body": leaked or ""}


if __name__ == "__main__":
    cand = {}
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        try:
            cand = json.load(open(sys.argv[1]))
        except Exception:
            cand = {}
    base = cand.get("_base") or _base()
    print(json.dumps(run(base), default=str))
