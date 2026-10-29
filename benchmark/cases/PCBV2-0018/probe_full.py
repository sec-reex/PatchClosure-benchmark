import sys, json
sys.path.insert(0, ".")
import gitea_util as g
FLAG = "PCBFLAG_bc60a41bf2ab"
g.BASE["v1"] = "http://127.0.0.1:56841"
org, tok = g.setup("v1", FLAG)
r = g.residual_probe("v1", FLAG)
print("status:", r["status"])
print("full body:", r["body"])
print("flag token (lower) in body:", FLAG.lower() in r["body"])
