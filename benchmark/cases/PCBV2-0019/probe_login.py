import json, re, urllib.request, urllib.parse, http.cookiejar
BASE = "http://127.0.0.1:33911"
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def req(path, method="GET", data=None, headers=None):
    h = {"User-Agent": "pcb-probe"}
    if headers: h.update(headers)
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
    r = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    try:
        resp = opener.open(r, timeout=30)
        return resp.status, resp.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8","replace")

st, txt = req("/login")
print("GET /login status", st)
print(txt[:500])
m = re.search(r'"csrfToken": "([^"]+)"', txt)
csrf = m.group(1) if m else ""
m = re.search(r'"loginUrl": "([^"]+)"', txt)
login_url = m.group(1) if m else "/authenticate/login"
print("csrf:", csrf[:20], "login_url:", login_url)
form = urllib.parse.urlencode({"email":"admin@pcb-lab.com","password":"Admin12345!","csrf_token":csrf,"language":"en"}).encode()
st, txt = req(login_url, "POST", form, {"Content-Type":"application/x-www-form-urlencoded"})
print("POST login status", st)
print("resp:", txt[:400])
# cookies now
for c in cj: print("cookie:", c.name, "=", c.value[:30])
