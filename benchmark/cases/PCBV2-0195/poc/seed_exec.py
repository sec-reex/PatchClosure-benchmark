#!/usr/bin/env python3
"""HTTP GET probe against the running SiYuan kernel.

Target host port comes from PCB_TARGET_PORT (verify.sh compose port --profile).
curl --path-as-is keeps the double-encoded %252e%252e segments intact.
"""
import json
import os
import subprocess
import sys


def run_probe(candidate, *, version="v1"):
    port = os.environ.get("PCB_TARGET_PORT")
    if not port:
        raise SystemExit("PCB_TARGET_PORT is required")
    base = f"http://127.0.0.1:{int(port)}"
    path = candidate["path"] if isinstance(candidate, dict) else str(candidate)
    proc = subprocess.run(
        ["curl", "--path-as-is", "-sS", "-m", "15", "-w", "\n%{http_code}", f"{base}{path}"],
        text=True,
        capture_output=True,
        check=False,
    )
    out = proc.stdout
    status, body = "", out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    return {"version": version, "path": path, "status": status, "body": body}


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
