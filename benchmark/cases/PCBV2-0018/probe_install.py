import json, re, time, urllib.request, urllib.error, base64

BASE = "http://127.0.0.1:56841"
ADMIN = "pcbadmin"
PASS = "Admin12345!"
AUTH = "Basic " + base64.b64encode(f"{ADMIN}:{PASS}".encode()).decode()

def req(method, path, data=None, headers=None, timeout=30, raw=False):
    url = BASE + path
    hdr = {"Accept": "application/json"}
    if headers: hdr.update(headers)
    body = None
    if data is not None:
        if raw:
            body = data.encode()
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            hdr["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        resp = urllib.request.urlopen(r, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace"), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.geturl() if hasattr(e,'geturl') else ""
    except Exception as e:
        return 0, str(e), ""

s, html, _ = req("GET", "/")
print("GET / status:", s, "has admin_name:", "admin_name" in html, "len:", len(html))
m = re.search(r'name="_csrf" content="([^"]+)"', html)
print("csrf found:", bool(m))
csrf = m.group(1) if m else ""
import urllib.parse
form = urllib.parse.urlencode({
    "_csrf": csrf, "db_type": "sqlite3", "db_path": "/data/gitea/gitea.db",
    "app_name": "Gitea", "repo_root_path": "/data/git/repositories", "run_user": "git",
    "domain": "localhost", "ssh_port": "22", "http_port": "3000",
    "app_url": "http://localhost:56841/", "log_root_path": "/data/gitea/log",
    "admin_name": ADMIN, "admin_passwd": PASS, "admin_confirm_passwd": PASS,
    "admin_email": "admin@pcb.local",
})
s, b, url = req("POST", "/", data=form, headers={"Content-Type": "application/x-www-form-urlencoded"}, raw=False)
print("POST install status:", s, "final url:", url)
print("body head:", b[:300])
time.sleep(2)
s2, b2, _ = req("GET", "/")
print("GET / after install:", s2, "has admin_name:", "admin_name" in b2, "head:", b2[:200])
s3, b3, _ = req("GET", "/api/v1/version")
print("version:", s3, b3[:200])
