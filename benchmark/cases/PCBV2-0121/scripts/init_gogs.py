#!/usr/bin/env python3
"""Idempotent Gogs install: POST /install, wait until /user/login is up."""
import re
import sys
import time

import requests

USER = "pcbadmin"
PASS = "Admin12345!"
EMAIL = "admin@pcb.local"


def _csrf(html: str) -> str:
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', html) or re.search(
        r'_csrf.*?content="([^"]+)"', html
    )
    return m.group(1) if m else ""


def wait_http(base: str, timeout: int = 300) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(base + "/", timeout=3, allow_redirects=False)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def installed(base: str) -> bool:
    try:
        r = requests.get(base + "/install", timeout=5, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            return "/install" not in loc
        r2 = requests.get(base + "/user/login", timeout=5, allow_redirects=False)
        return r2.status_code == 200 and "user_name" in (r2.text or "")
    except Exception:
        return False


def install(base: str) -> bool:
    if installed(base):
        return True
    data = {
        "db_type": "SQLite3",
        "db_path": "/data/gogs/gogs.db",
        "app_name": "Gogs",
        "repo_root_path": "/data/git/gogs-repositories",
        "run_user": "git",
        "domain": "localhost",
        "ssh_port": "22",
        "http_port": "3000",
        "app_url": "http://localhost:3000/",
        "log_root_path": "/data/gogs/log",
        "smtp_host": "",
        "admin_name": USER,
        "admin_passwd": PASS,
        "admin_confirm_passwd": PASS,
        "admin_email": EMAIL,
    }
    try:
        s = requests.Session()
        r = s.get(base + "/install", timeout=15)
        tok = _csrf(r.text)
        if tok:
            data["_csrf"] = tok
        r = s.post(base + "/install", data=data, timeout=45, allow_redirects=False)
        if r.status_code not in (200, 302, 303):
            print(f"install http {r.status_code}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"install error: {e}", file=sys.stderr)
        return False
    t0 = time.time()
    while time.time() - t0 < 90:
        if installed(base):
            return True
        time.sleep(2)
    return installed(base)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: init_gogs.py PORT", file=sys.stderr)
        return 20
    base = f"http://127.0.0.1:{int(sys.argv[1])}"
    if not wait_http(base):
        print("gogs not ready", file=sys.stderr)
        return 20
    if not install(base):
        print("gogs install failed", file=sys.stderr)
        return 20
    print(f"gogs ready at {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
