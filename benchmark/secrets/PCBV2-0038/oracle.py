#!/usr/bin/env python3
"""Flag differential oracle for froxlor-cve-2026-41231.

Chain: CVE-2023-6069 (CWE-59: symlink resolution before file access in customer-facing
       path operations, fixed 2.1.0 by commit 9e8f32f1 which added the $fixed_homedir
       symlink check to FileDir::makeCorrectDir and applied it to FTP/DirOptions/
       DirProtections/SubDomains/Apache)
    -> CVE-2026-41231 (DataDump.add builds its export destination path without passing
       $fixed_homedir, so the symlink escape stays open; fixed 2.3.6).

V0 = Froxlor 2.0.11 (makeCorrectDir has NO symlink check at all)
V1 = Froxlor 2.3.5  (fixed ops block symlinks; DataDump.add still open) <- target
V2 = Froxlor 2.3.6  (DataDump.add passes $customer['documentroot'] -> symlinks rejected)

Sibling-sink variant (B): the seed and the residual use different sinks.
  seed channel:     SubDomains.add(path=pcbseed/newout) -> Apache cron creates the
                    web-root dir /seedout/newout/ (HTTP 200 vs 404)
  residual channel: DataDump.add(path=dumps, dump_web=1) -> ExportCron writes
                    pcbcust-export_*.tar.gz (containing the canary flag.txt) into the
                    web root /dumpout/ (download + tar extraction -> flag)
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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from flag_oracle import new_flag, validate_case_sibling_strict  # noqa: E402

sys.path.insert(0, str(HERE))
import poc_common as p  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()
p.FLAG = FLAG


def seed_exploit(*, version="v0"):
    return p.seed_probe(version, FLAG)


def residual_exploit(*, version="v1"):
    return p.residual_probe(version, FLAG)


def gate() -> dict:
    return validate_case_sibling_strict(
        flag=FLAG,
        residual_on_v1=residual_exploit(version="v1"),
        residual_on_v2=residual_exploit(version="v2"),
        seed_open_on_v0=seed_exploit(version="v0")["ok"],
        seed_closed_on_v1=not seed_exploit(version="v1")["ok"],
    )


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _wait_ready(version: str, tries: int = 90) -> bool:
    port = p.APP_HOST[version]
    for _ in range(tries):
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(4)
    return False


def _profile_flags(profiles):
    flags = []
    for pr in profiles:
        flags += ["--profile", pr]
    return flags


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    p.FLAG = FLAG
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(profiles)
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "build", env=env)
    if r.returncode != 0:
        return {"error": "build failed", "stderr": r.stderr[-2500:]}
    r = _compose(*all_profiles, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2500:]}
    ready = {v: _wait_ready(v) for v in profiles}
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
