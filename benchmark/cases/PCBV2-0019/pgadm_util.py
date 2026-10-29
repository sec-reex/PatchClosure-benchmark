#!/usr/bin/env python3
"""Shared pgAdmin HTTP plumbing for the pgadmin-* benchmark cases.

Login (server mode), CSRF handling, and the standard "register the
sidecar PostgreSQL server in pgAdmin" flow used by the seed and the
residual probes. The canary is planted in the DATABASE by the postgres
entrypoint (pg_init.sh); this module only ever talks to pgAdmin's own
HTTP API.
"""
import re
import time

import requests

ADMIN_EMAIL = "admin@pcb-lab.com"
ADMIN_PASS = "Admin12345!"

BASE = {
    "v0": "http://127.0.0.1:33910",
    "v1": "http://127.0.0.1:33911",
    "v2": "http://127.0.0.1:33912",
}

PG_HOST = {"v0": "pg_v0", "v1": "pg_v1", "v2": "pg_v2"}
PG_CONTAINER = {"v0": "pcb-pga-v0-pg", "v1": "pcb-pga-v1-pg", "v2": "pcb-pga-v2-pg"}
PG_PASS = "pcbpass"


def wait_ready(version: str, timeout: int = 240) -> bool:
    base = BASE[version]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{base}/login", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def login(version: str):
    """Return a requests.Session authenticated as the pgAdmin admin user."""
    base = BASE[version]
    s = requests.Session()
    r = s.get(f"{base}/login", timeout=20)
    m = re.search(r'"csrfToken": "([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    m = re.search(r'"loginUrl": "([^"]+)"', r.text)
    login_url = m.group(1) if m else "/authenticate/login"
    r = s.post(
        f"{base}{login_url}",
        data={"email": ADMIN_EMAIL, "password": ADMIN_PASS,
              "csrf_token": csrf, "language": "en"},
        timeout=30,
    )
    # Grab the post-login CSRF token from the browser JS config page.
    r = s.get(f"{base}/browser/js/utils.js", timeout=20)
    m = re.search(r"pgAdmin\['csrf_token'\] = '([^']+)'", r.text)
    s.headers["X-pgA-CSRFToken"] = m.group(1) if m else ""
    return s


def ensure_server(version: str, s: requests.Session) -> int:
    """Register (or find) the sidecar Postgres as pgAdmin server; return sid."""
    base = BASE[version]
    r = s.get(f"{base}/browser/server/obj/1", timeout=20)
    if r.status_code == 200:
        try:
            for node in (r.json().get("data") or []):
                if node.get("name") == "pg" and node.get("id"):
                    return node["id"]
        except Exception:
            pass
    payload = {
        "name": "pg",
        "host": PG_HOST[version],
        "port": 5432,
        "db": "postgres",
        "username": "postgres",
        "password": PG_PASS,
        "ssl_mode": "prefer",
        "maintenance_db": "postgres",
        "save_password": True,
        "comment": "",
    }
    r = s.post(f"{base}/browser/server/obj/1", json=payload, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(
            f"server create failed: {r.status_code} {r.text[:300]}"
        )
    try:
        sid = int(r.json()["node"]["_id"])
    except Exception:
        raise RuntimeError(
            f"could not parse server create response: {r.text[:300]}"
        )
    # Establish the DB connection with the saved password so the tree
    # APIs below know the server version.
    c = s.post(
        f"{base}/browser/server/connect/1/{sid}",
        json={"password": PG_PASS}, timeout=40,
    )
    if c.status_code not in (200, 201) and c.status_code != 410:
        raise RuntimeError(f"server connect failed: {c.status_code} {c.text[:300]}")
    return sid


def get_did(version: str, s: requests.Session, sid: int) -> int:
    """OID of the 'postgres' database."""
    base = BASE[version]
    r = s.get(f"{base}/browser/database/obj/1/{sid}", timeout=20)
    r.raise_for_status()
    for node in (r.json() or []):
        if node.get("name") == "postgres":
            return node["oid"]
    raise RuntimeError("postgres database not found in pgAdmin tree")


def get_scid(version: str, s: requests.Session, sid: int, did: int) -> int:
    """OID of the 'public' schema."""
    base = BASE[version]
    r = s.get(
        f"{base}/browser/schema/obj/1/{sid}/{did}",
        timeout=20,
    )
    r.raise_for_status()
    for node in (r.json() or []):
        if node.get("name") == "public":
            return node["oid"]
    raise RuntimeError("public schema not found in pgAdmin tree")
