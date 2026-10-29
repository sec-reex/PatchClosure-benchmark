#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import subprocess
import sys

FUC = "/assets/lib/fuc.js.php"
BASE = {
    "v0": "http://127.0.0.1:39001",
    "v1": "http://127.0.0.1:39002",
    "v2": "http://127.0.0.1:39003",
}


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    url_param = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    proc = subprocess.run(
        [
            "curl", "-sS", "-m", "15", "-G",
            "--data-urlencode", "url=%s" % url_param,
            "-H", "Host: 127.0.0.1",
            "-H", "Referer: http://127.0.0.1/",
            "-w", "\n%{http_code}",
            "%s%s" % (base, FUC),
        ],
        text=True, capture_output=True, check=False,
    )
    out = proc.stdout
    status, body = "", out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    return {"version": version, "url": url_param, "status": status, "body": body}


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
