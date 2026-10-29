#!/usr/bin/env python3
"""Host-side Daptin HTTP helpers.

The official daptin/daptin image has no curl/python3. Canary seeding and
probes run from the host against the published 8080 mapping.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ADMIN = {"name": "pcbadmin", "email": "admin@pcb.test", "password": "PcbAdm1n!Str0ng9"}
ATTACKER = {"name": "attacker", "email": "attacker@pcb.test", "password": "Att4ck3r!PwD9"}


def _request(method: str, url: str, headers=None, body=None, timeout: int = 20):
    req = urllib.request.Request(
        url,
        data=body,
        headers=headers or {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        return e.code, raw
    except Exception:
        return 0, ""


def _json_body(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


def wait_api(base: str, tries: int = 90) -> bool:
    url = f"{base.rstrip('/')}/api/world"
    for _ in range(tries):
        code, text = _request("GET", url, timeout=5)
        if '"data"' in text or code in (200, 401, 403):
            return True
        time.sleep(2)
    return False


def register(base: str, name: str, email: str, password: str) -> None:
    _request(
        "POST",
        f"{base.rstrip('/')}/action/user_account/signup",
        headers={"Content-Type": "application/json"},
        body=_json_body({
            "attributes": {
                "name": name,
                "email": email,
                "password": password,
                "passwordConfirm": password,
            }
        }),
        timeout=20,
    )


def login(base: str, email: str, password: str) -> str:
    code, text = _request(
        "POST",
        f"{base.rstrip('/')}/action/user_account/signin",
        headers={"Content-Type": "application/json"},
        body=_json_body({"attributes": {"email": email, "password": password}}),
        timeout=20,
    )
    try:
        parsed = json.loads(text)
    except Exception:
        return ""
    items = parsed if isinstance(parsed, list) else [parsed]
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("ResponseType") == "client.store.set":
            attrs = item.get("Attributes") or {}
            val = attrs.get("value")
            if isinstance(val, str) and val:
                return val
    return ""


def seed_canary(base: str, flag: str, container_id: str) -> bool:
    """Register admin, create pcb_canary, restart, insert flag. Idempotent."""
    register(base, ADMIN["name"], ADMIN["email"], ADMIN["password"])
    token = login(base, ADMIN["email"], ADMIN["password"])
    if not token:
        print("daptin_api: admin login failed", file=sys.stderr)
        return False

    schema = json.dumps({
        "Columns": [{
            "Name": "token",
            "ColumnName": "token",
            "ColumnType": "label",
            "DataType": "varchar(500)",
            "IsNullable": False,
        }],
        "DefaultPermission": 0,
    })
    _request(
        "POST",
        f"{base.rstrip('/')}/api/world",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        },
        body=_json_body({
            "data": {
                "type": "world",
                "attributes": {
                    "table_name": "pcb_canary",
                    "world_schema_json": schema,
                    "permission": 0,
                    "is_hidden": 1,
                },
            }
        }),
        timeout=30,
    )

    if container_id:
        subprocess.run(
            ["docker", "restart", container_id],
            capture_output=True, check=False, timeout=60,
        )
        if not wait_api(base, tries=45):
            print("daptin_api: API not ready after restart", file=sys.stderr)
            return False

    token = login(base, ADMIN["email"], ADMIN["password"])
    if not token:
        print("daptin_api: admin re-login failed", file=sys.stderr)
        return False

    code, text = _request(
        "POST",
        f"{base.rstrip('/')}/api/pcb_canary",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        },
        body=_json_body({
            "data": {
                "type": "pcb_canary",
                "attributes": {"token": flag},
            }
        }),
        timeout=30,
    )
    try:
        resp = json.loads(text)
    except Exception:
        resp = {}
    ok = isinstance(resp.get("data"), dict) and resp["data"].get("type") == "pcb_canary"
    if not ok:
        print(f"daptin_api: canary insert failed http={code} body={text[:200]}", file=sys.stderr)
    return ok


def attacker_token(base: str) -> str:
    register(base, ATTACKER["name"], ATTACKER["email"], ATTACKER["password"])
    return login(base, ATTACKER["email"], ATTACKER["password"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["wait", "seed"])
    ap.add_argument("--base", required=True)
    ap.add_argument("--flag", default="")
    ap.add_argument("--container", default="")
    args = ap.parse_args()
    if args.cmd == "wait":
        return 0 if wait_api(args.base) else 1
    if not args.flag:
        print("seed requires --flag", file=sys.stderr)
        return 1
    return 0 if seed_canary(args.base, args.flag, args.container) else 1


if __name__ == "__main__":
    sys.exit(main())
