"""Shared plumbing for astro-cve-2026-59729 (HTTP echo observation)."""

import json
import urllib.request

BASE = {"v0": "http://127.0.0.1:33890", "v1": "http://127.0.0.1:33891", "v2": "http://127.0.0.1:33892"}


def exploit(version: str, mode: str):
    try:
        with urllib.request.urlopen(f"{BASE[version]}/{mode}", timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {"flag": ""}
