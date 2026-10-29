import http.cookiejar, json, re, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:56841"
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def req(method, path, data=None, timeout=30):
    url = BASE + path
    hdr = {"Accept": "application/json"}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        resp = opener.open(r, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace"), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), e.geturl() if hasattr(e,'geturl') else ""
    except Exception as e:
        return 0, str(e), ""

import urllib.parse
s, html, _ = req("GET", "/")
print("GET / status:", s, "has admin:", "admin_name" in html)
cookies = [(c.name, c.value) for c in cj]
print("cookies:", cookies)
csrf_cookie = None
for c in cj:
    if "csrf" in c.name.lower():
        csrf_cookie = c.value
print("csrf cookie:", csrf_cookie)
m = re.search(r'name="_csrf" content="([^"]+)"', html)
print("csrf meta:", m.group(1) if m else None)
form = {
    "_csrf": csrf_cookie or "",
    "db_type": "sqlite3", "db_path": "/data/gitea/gitea.db",
    "app_name": "Gitea", "repo_root_path": "/data/git/repositories", "run_user": "git",
    "domain": "localhost", "ssh_port": "22", "http_port": "3000",
    "app_url": "http://localhost:56841/", "log_root_path": "/data/gitea/log",
    "admin_name": "pcbadmin", "admin_passwd": "Admin12345!", "admin_confirm_passwd": "Admin12345!",
    "admin_email": "admin@pcb.local",
}
s, b, url = req("POST", "/", data=form)
print("POST status:", s, "url:", url)
print("body head:", b[:200])
time.sleep(3)
s2, b2, _ = req("GET", "/")
print("GET after:", s2, "has admin:", "admin_name" in b2)
s3, b3, _ = req("GET", "/api/v1/version")
print("version:", s3, b3[:200])
