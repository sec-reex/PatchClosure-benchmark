#!/usr/bin/env python3
"""Flag differential oracle for gitea-cve-2026-25714.

Chain: CVE-2025-68941 (public-only token leaks private resources)
     -> CVE-2026-25714 (/user/orgs missed by checkTokenPublicOnly).

V0 = Gitea 1.22.2  (no public-only enforcement)
V1 = Gitea 1.26.1  (checkTokenPublicOnly for repo/org APIs; /user/orgs unguarded) <- target
V2 = Gitea 1.26.2  (PR #37118: FindOrgOptions.ApplyPublicOnly filters private orgs)

The setup creates a PRIVATE org pcb_<FLAG> and a PRIVATE repo secret_<FLAG> (names
embed the eval-injected flag) plus a public-only token.

seed:     GET /orgs/{org}/repos   -> v0 lists private repo, v1 403
residual: GET /user/orgs          -> v1 lists private org, v2 filters it out
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gitea_util as g  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def seed_exploit(*, version="v0") -> dict:
    if not g.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    return g.seed_probe(version, FLAG)


def residual_exploit(*, version="v1") -> dict:
    if not g.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    return g.residual_probe(version, FLAG)


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
        "seed_v0_status": s0["status"],
        "seed_v1_status": s1["status"],
        "residual_v1_status": r1["status"],
        "residual_v2_status": r2["status"],
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
    _compose(*all_profiles, "down", "-v", "--remove-orphans", env=env)
    r = _compose(*all_profiles, "up", "-d", "--wait", "--wait-timeout", "600", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    result = gate()
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true", help="run gate against already-up envs")
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
