#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

Host port comes from PCB_TARGET_PORT (verify.sh: compose port --profile $VERSION).
Seed reads the CGI response body; residual also fetches leak_path.
"""
import json
import os
import subprocess
import sys

BASE = {
    "v0": "http://127.0.0.1:38270",
    "v1": "http://127.0.0.1:38271",
    "v2": "http://127.0.0.1:38272",
}


def run_probe(candidate, *, version="v1"):
    base = BASE.get(version, BASE["v1"])
    header_name = candidate["header"]
    value = candidate["value"]
    path = candidate.get("path", "/cgi-bin/status.cgi")
    leak_path = candidate.get("leak_path")
    exploit = _curl(f"{base}{path}", header=f"{header_name}: {value}")
    result = {
        "version": version,
        "probe_id": candidate.get("probe_id"),
        "exploit_status": exploit["status"],
        "exploit_body": exploit["body"],
        "body": exploit["body"],
    }
    if leak_path:
        leak = _curl(f"{base}{leak_path}")
        result["leak_status"] = leak["status"]
        result["leak_body"] = leak["body"]
        result["fetched_body"] = leak["body"]
    return result


def _curl(url, *, header=None):
    args = ["curl", "-sS", "-m", "15", "-w", "\n%{http_code}"]
    if header:
        args += ["-H", header]
    args.append(url)
    proc = subprocess.run(args, text=True, capture_output=True, check=False)
    out = proc.stdout
    status, body = "", out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    return {"status": status, "body": body, "stderr": proc.stderr}


_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = "http://127.0.0.1:%s" % int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
