import sys
sys.path.insert(0, ".")
import gitea_util as g
import requests
FLAG = "PCBFLAG_bc60a41bf2ab"
g.BASE["v1"] = "http://127.0.0.1:56841"
org, tok = g.setup("v1", FLAG)
r = requests.get(f"{g.BASE['v1']}/api/v1/user/orgs",
                 headers={"Authorization": f"token {tok}"}, timeout=15)
print("status:", r.status_code)
print("full body:", r.text)
print("FLAG_TOKEN_PRESENT:", FLAG.lower() in r.text)
