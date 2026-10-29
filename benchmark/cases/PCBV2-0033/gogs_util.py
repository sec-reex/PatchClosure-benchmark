"""Shared utilities for the Gogs webhook-SSRF benchmark case.

Handles Gogs installation, admin token, repo creation, webhook creation
(API), test delivery (UI POST), and reading the hook delivery-history page
where the redirected-to internal canary response body is rendered.
"""
import re
import subprocess
import tempfile
import time
import os

import requests

ADMIN_USER = "pcbadmin"
ADMIN_PASS = "Admin12345!"
ADMIN_EMAIL = "admin@pcb.local"
REPO_NAME = "testrepo"

CONTAINERS = {"v0": "pcb-gogs-v0", "v1": "pcb-gogs-v1", "v2": "pcb-gogs-v2"}
PORTS = {"v0": 33670, "v1": 33671, "v2": 33672}


def base_url(version: str) -> str:
    return f"http://127.0.0.1:{PORTS[version]}"


def wait_ready(version: str, timeout: int = 240) -> bool:
    url = base_url(version)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/", timeout=3)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def install_gogs(version: str) -> bool:
    url = base_url(version)
    data = {
        "db_type": "SQLite3",
        "db_path": "/data/gogs/gogs.db",
        "app_name": "Gogs",
        "repo_root_path": "/data/git/gogs-repositories",
        "run_user": "git",
        "domain": "localhost",
        "ssh_port": "22",
        "http_port": "3000",
        "app_url": f"http://localhost:3000/",
        "log_root_path": "/data/gogs/log",
        "smtp_host": "",
        "admin_name": ADMIN_USER,
        "admin_passwd": ADMIN_PASS,
        "admin_confirm_passwd": ADMIN_PASS,
        "admin_email": ADMIN_EMAIL,
    }
    try:
        s = requests.Session()
        r = s.get(f"{url}/install", timeout=10)
        csrf = _extract_csrf(r.text)
        if csrf:
            data["_csrf"] = csrf
        r = s.post(f"{url}/install", data=data, timeout=30, allow_redirects=False)
        return r.status_code in (200, 302, 303)
    except Exception as e:
        print(f"  install error: {e}")
        return False


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="_csrf" content="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'value="([0-9a-f]{32,})"[^>]*name="_csrf"', html)
    if m:
        return m.group(1)
    m = re.search(r'name="_csrf"\s+value="([0-9a-f]{32,})"', html)
    if m:
        return m.group(1)
    m = re.search(r'"csrfToken"\s*:\s*"([^"]+)"', html)
    return m.group(1) if m else ""


def create_token(version: str) -> str:
    url = base_url(version)
    last = None
    for i in range(8):
        name = f"pcb_token_{int(time.time() * 1000)}_{i}"
        r = requests.post(
            f"{url}/api/v1/users/{ADMIN_USER}/tokens",
            auth=(ADMIN_USER, ADMIN_PASS),
            json={"name": name},
            timeout=10,
        )
        if r.status_code == 201:
            return r.json()["sha1"]
        if r.status_code == 404:
            time.sleep(5)
            continue
        last = r
        time.sleep(3)
    raise RuntimeError(f"create_token failed: {last.status_code if last else 'n/a'} {last.text[:100] if last else ''}")


def create_repo(version: str, token: str) -> dict:
    url = base_url(version)
    r = requests.post(
        f"{url}/api/v1/user/repos",
        headers={"Authorization": f"token {token}"},
        json={"name": REPO_NAME, "auto_init": False},
        timeout=15,
    )
    if r.status_code == 422:
        # repo already exists
        return {"name": REPO_NAME}
    r.raise_for_status()
    repo_info = r.json()

    clone_url = f"http://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1:{PORTS[version]}/{ADMIN_USER}/{REPO_NAME}.git"
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, REPO_NAME)
        os.makedirs(repo_dir)
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0",
               "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", "init", repo_dir], capture_output=True, timeout=10)
        subprocess.run(["git", "-C", repo_dir, "checkout", "-b", "master"],
                       capture_output=True, timeout=10)
        with open(os.path.join(repo_dir, "README.md"), "w") as f:
            f.write("# test repo\n")
        subprocess.run(["git", "-C", repo_dir, "add", "."], capture_output=True, timeout=10)
        subprocess.run(["git", "-C", repo_dir, "commit", "-m", "init"],
                       capture_output=True, timeout=10, env=env)
        subprocess.run(["git", "-C", repo_dir, "remote", "add", "origin", clone_url],
                       capture_output=True, timeout=10)
        r2 = subprocess.run(["git", "-C", repo_dir, "push", "-u", "origin", "master"],
                            capture_output=True, text=True, timeout=30, env=env)
        if r2.returncode != 0:
            print(f"  init push failed: {r2.stderr}")
    return repo_info


def create_webhook_api(version: str, token: str, url: str) -> int:
    """Create a webhook on the test repo via API (no localCIDR validation)."""
    base = base_url(version)
    r = requests.post(
        f"{base}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/hooks",
        headers={"Authorization": f"token {token}"},
        json={
            "type": "gogs",
            "config": {"url": url, "content_type": "json"},
            "events": ["push"],
            "active": True,
        },
        timeout=15,
    )
    if r.status_code == 422:
        # hook with same URL may already exist: list and reuse
        lst = requests.get(
            f"{base}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/hooks",
            headers={"Authorization": f"token {token}"}, timeout=15)
        for h in lst.json():
            if h.get("config", {}).get("url") == url:
                return h["id"]
    r.raise_for_status()
    return r.json()["id"]


def login_session(version: str) -> requests.Session:
    """Login as admin, return an authed session (with CSRF token)."""
    base = base_url(version)
    s = requests.Session()
    s.get(f"{base}/user/login", timeout=10)
    r = s.get(f"{base}/user/login", timeout=10)
    csrf = _extract_csrf(r.text)
    r = s.post(
        f"{base}/user/login",
        data={"_csrf": csrf, "user_name": ADMIN_USER, "password": ADMIN_PASS},
        timeout=15, allow_redirects=False,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f"login failed: {r.status_code}")
    # home page to refresh CSRF
    r = s.get(f"{base}/", timeout=10)
    s.headers["_csrf"] = _extract_csrf(r.text)
    return s


def trigger_test_delivery(version: str, hook_id: int) -> bool:
    """POST the webhook 'Test Delivery' button (per-event test, synchronous task)."""
    base = base_url(version)
    s = login_session(version)
    r = s.post(
        f"{base}/{ADMIN_USER}/{REPO_NAME}/settings/hooks/{hook_id}/test",
        data={"_csrf": s.headers.get("_csrf", "")},
        timeout=20, allow_redirects=False,
    )
    return r.status_code in (200, 302, 303)


def read_hook_delivery_body(version: str, hook_id: int, retries: int = 12) -> str:
    """GET the hook delivery-history page; return all delivery response bodies.

    The page renders .ResponseInfo.Body for each hook task. Returns empty
    string when no delivery record exists yet (or delivery was blocked before
    any response was captured).
    """
    base = base_url(version)
    s = login_session(version)
    bodies = []
    for _ in range(retries):
        r = s.get(f"{base}/{ADMIN_USER}/{REPO_NAME}/settings/hooks/{hook_id}", timeout=10)
        html = r.text
        # Response bodies are rendered inside <pre class="raw"><code class="nohighlight">...</code></pre>
        codes = re.findall(
            r'<pre class="raw"><code class="nohighlight">(.*?)</code></pre>',
            html, re.S,
        )
        if codes:
            bodies = [c.strip() for c in codes]
            if any(b for b in bodies):
                return "\n".join(bodies)
        time.sleep(3)
    return "\n".join(bodies)
