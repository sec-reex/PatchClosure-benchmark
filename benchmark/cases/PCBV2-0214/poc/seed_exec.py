#!/usr/bin/env python3
"""HTTP probe against the real XWiki ssx/jsx resource endpoint.

Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

BASE = {
    "v0": "http://127.0.0.1:38610",
    "v1": "http://127.0.0.1:38611",
    "v2": "http://127.0.0.1:38612",
}


def _base_url(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    return BASE[version]


def run_probe(candidate, *, version="v1"):
    base = _base_url(version)
    path = candidate["path"] if isinstance(candidate, dict) else str(candidate)
    url = f"{base}{path}"
    result = {"version": version, "path": path, "status": "", "body": ""}
    for attempt in range(8):
        proc = subprocess.run(
            ["curl", "--path-as-is", "-sS", "-m", "30", "-w", "\n%{http_code}", url],
            text=True,
            capture_output=True,
            check=False,
        )
        out = proc.stdout or ""
        status = ""
        body = out
        if "\n" in out:
            body, status = out.rsplit("\n", 1)
        result = {
            "version": version,
            "path": path,
            "status": status.strip(),
            "body": body,
        }
        if proc.returncode == 0:
            return result
        result["error"] = (proc.stderr or "").strip() or f"curl rc={proc.returncode}"
        time.sleep(2)
    return result


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
