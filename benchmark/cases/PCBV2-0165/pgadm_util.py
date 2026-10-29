#!/usr/bin/env python3
"""Shared pgAdmin HTTP plumbing for pgadmin-cve-2026-17348.

This case is about routes missing @pga_login_required: the probes are
ANONYMOUS requests (no pgAdmin session). The only thing they need is a
valid CSRF token, harvested the same way the upstream regression test
does it -- from GET /login -- because pgAdmin's CSRF protection
(WTF_CSRF_METHODS includes GET) covers every route including
unauthenticated ones.
"""
import re
import time

import requests

BASE = {
    "v0": "http://127.0.0.1:33920",
    "v1": "http://127.0.0.1:33921",
    "v2": "http://127.0.0.1:33922",
}

AUTH_REJECT = (301, 302, 401, 403)


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


def anonymous_session(version: str) -> requests.Session:
    """Session with a valid CSRF token but NO authenticated pgAdmin login."""
    base = BASE[version]
    s = requests.Session()
    r = s.get(f"{base}/login", timeout=20)
    m = re.search(r'"csrfToken": "([^"]+)"', r.text)
    s.headers["X-pgA-CSRFToken"] = m.group(1) if m else ""
    return s


def is_reached(resp: requests.Response) -> bool:
    """A request 'reached' the route body iff the auth decorator did NOT
    reject it. Mirrors the upstream regression test (test_close_requires_auth)
    which asserts blocked == status in (301, 302, 401, 403) and status != 200."""
    return resp.status_code not in AUTH_REJECT
