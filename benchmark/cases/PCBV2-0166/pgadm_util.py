#!/usr/bin/env python3
"""Shared pgAdmin HTTP plumbing for pgadmin-cve-2026-17351.

Login, server registration, and the query-tool transaction setup that the
AI Assistant chat route requires (trans_id must exist in the session
gridData before /nlq/chat/<trans_id>/stream will run).
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path

import requests

ADMIN_EMAIL = "admin@pcb-lab.com"
ADMIN_PASS = "Admin12345!"

BASE = {
    "v0": "http://127.0.0.1:33930",
    "v1": "http://127.0.0.1:33931",
    "v2": "http://127.0.0.1:33932",
}

PG_HOST = {"v0": "pg_v0", "v1": "pg_v1", "v2": "pg_v2"}
PG_PASS = "pcbpass"


def _apply_dynamic_base():
    port = (os.environ.get("PCB_TARGET_PORT") or "").strip()
    if port:
        url = f"http://127.0.0.1:{port}"
        for k in list(BASE):
            BASE[k] = url
    base = (os.environ.get("PCB_BASE") or "").strip()
    if base:
        for k in list(BASE):
            BASE[k] = base.rstrip("/")


_apply_dynamic_base()


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
    base = BASE[version]
    s = requests.Session()
    r = s.get(f"{base}/login", timeout=20)
    m = re.search(r'"csrfToken": "([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    m = re.search(r'"loginUrl": "([^"]+)"', r.text)
    login_url = m.group(1) if m else "/authenticate/login"
    s.post(
        f"{base}{login_url}",
        data={"email": ADMIN_EMAIL, "password": ADMIN_PASS,
              "csrf_token": csrf, "language": "en"},
        timeout=30,
    )
    r = s.get(f"{base}/browser/js/utils.js", timeout=20)
    m = re.search(r"pgAdmin\['csrf_token'\] = '([^']+)'", r.text)
    s.headers["X-pgA-CSRFToken"] = m.group(1) if m else ""
    return s


def ensure_server(version: str, s: requests.Session) -> int:
    base = BASE[version]
    r = s.get(f"{base}/browser/server/obj/1", timeout=20)
    sid = None
    if r.status_code == 200:
        try:
            for node in (r.json() or []):
                if node.get("name") == "pg" and node.get("id"):
                    sid = node["id"]
                    break
        except Exception:
            pass
    if sid is None:
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
                f"server create failed: {r.status_code} {r.text[:300]}")
        try:
            sid = int(r.json()["node"]["_id"])
        except Exception:
            raise RuntimeError(f"could not parse server create: {r.text[:300]}")
    s.post(
        f"{base}/browser/server/connect/1/{sid}",
        json={"password": PG_PASS}, timeout=40,
    )
    return sid


def get_did(version: str, s: requests.Session, sid: int) -> int:
    base = BASE[version]
    r = s.get(f"{base}/browser/database/obj/1/{sid}", timeout=20)
    r.raise_for_status()
    for node in (r.json() or []):
        if node.get("name") == "postgres":
            return node["oid"]
    raise RuntimeError("postgres database not found in pgAdmin tree")


def init_query_tool(version: str, s: requests.Session, sid: int, did: int,
                    trans_id: int = 424242) -> bool:
    """Create a query-tool transaction in the session (CSRF-exempt route)."""
    base = BASE[version]
    r = s.post(
        f"{base}/sqleditor/initialize/sqleditor/{trans_id}/1/{sid}/{did}",
        data=json.dumps({"dbname": "postgres"}),
        headers={"Content-Type": "application/json"},
        timeout=40,
    )
    return r.status_code in (200, 201)


def read_flag_file(version: str) -> str:
    """docker compose exec read of COPY TO PROGRAM output in the PG service."""
    proj = os.environ.get("COMPOSE_PROJECT_NAME") or ""
    case_dir = os.environ.get("CASE_DIR") or str(Path(__file__).resolve().parent)
    svc = f"pg_{version}"
    if proj:
        cmd = [
            "docker", "compose", "-p", proj, "--project-directory", case_dir,
            "exec", "-T", svc, "sh", "-c",
            "cat /tmp/pcb_result.txt 2>/dev/null || true",
        ]
    else:
        cmd = [
            "docker", "exec", f"pcb-pgc-{version}-pg", "sh", "-c",
            "cat /tmp/pcb_result.txt 2>/dev/null || true",
        ]
    out = subprocess.run(
        cmd, capture_output=True, text=True, timeout=30,
    ).stdout
    return out.strip()
