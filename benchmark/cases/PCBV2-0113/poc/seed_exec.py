#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from poc_common import run_payload  # noqa: E402


def run_probe(candidate, *, version="v1"):
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    return run_payload(payload, version)


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("VERSION") or "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
