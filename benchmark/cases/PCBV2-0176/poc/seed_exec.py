#!/usr/bin/env python3
"""Probe: POST /set {pointer,value} then GET /check against the json-ptr Express service.

Usage: python3 seed_exec.py <candidate.json> [version]

Restarts the node process before each probe so leftover Object.prototype pollution
cannot leak from seed into residual (or across retries).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent
SVC = {"v0": "v0", "v1": "v1", "v2": "v2"}
BASE = {
    "v0": "http://127.0.0.1:39881",
    "v1": "http://127.0.0.1:39882",
    "v2": "http://127.0.0.1:39883",
}

_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = f"http://127.0.0.1:{int(_pt)}"
_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt


def _curl(args, tries=8, sleep=0.5):
    out, status = "", ""
    for _ in range(tries):
        proc = subprocess.run(args, text=True, capture_output=True, check=False)
        out = proc.stdout or ""
        m = re.search(r"HTTPSTATUS:(\d+)", out)
        status = m.group(1) if m else ""
        if m:
            out = out[: m.start()]
        if status and status != "000":
            break
        time.sleep(sleep)
    return out, status


def _restart(version: str) -> None:
    env = dict(os.environ)
    cmd = ["docker", "compose"]
    proj = os.environ.get("COMPOSE_PROJECT_NAME")
    if proj:
        cmd += ["-p", proj]
    cmd += ["--profile", version, "restart", SVC.get(version, version)]
    subprocess.run(cmd, cwd=str(CASE_DIR), text=True, capture_output=True, check=False, env=env)


def _post_set(version, pointer, value):
    url = f"{BASE[version]}/set"
    payload = json.dumps({"pointer": pointer, "value": value})
    return _curl([
        "curl", "-sS", "-m", "10", "-H", "Content-Type: application/json",
        "-d", payload, "-w", "HTTPSTATUS:%{http_code}", url,
    ])


def _get_check(version):
    url = f"{BASE[version]}/check"
    return _curl(["curl", "-sS", "-m", "10", "-w", "HTTPSTATUS:%{http_code}", url])


def _wait_ready(version, tries=60):
    for _ in range(tries):
        body, status = _post_set(version, ["ok"], 1)
        if status == "200":
            return True
        time.sleep(0.5)
    return False


def run_probe(candidate, *, version="v1"):
    pointer = candidate["pointer"] if isinstance(candidate, dict) else candidate
    value = candidate.get("value", True) if isinstance(candidate, dict) else True
    _restart(version)
    _wait_ready(version)
    set_body, set_status = _post_set(version, pointer, value)
    check_body, check_status = _get_check(version)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id") if isinstance(candidate, dict) else None,
        "set_status": set_status,
        "set_body": set_body,
        "check_status": check_status,
        "check_body": check_body,
        "body": check_body,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
