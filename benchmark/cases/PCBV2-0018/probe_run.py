import sys
sys.path.insert(0, ".")
import gitea_util as g

FLAG = "PCBFLAG_bc60a41bf2ab"
g.BASE["v1"] = "http://127.0.0.1:56841"
print("wait_ready:", g.wait_ready("v1"))
org, tok = g.setup("v1", FLAG)
print("org:", org, "tok set:", bool(tok))
if tok:
    r = g.residual_probe("v1", FLAG)
    print("RESIDUAL status:", r["status"])
    print("RESIDUAL body:", r["body"])
    print("RESIDUAL ok:", r["ok"])
    r2 = g.seed_probe("v1", FLAG)
    print("SEED status:", r2["status"])
    print("SEED body:", r2["body"])
    print("SEED ok:", r2["ok"])
