import sys
sys.path.insert(0, ".")
import gitea_util as g

FLAG = "PCBFLAG_a377cb4d004d"
# point v1 at the actually-running container port
g.BASE["v1"] = "http://127.0.0.1:56841"
print("wait_ready:", g.wait_ready("v1"))
org, tok = g.setup("v1", FLAG)
print("org:", org, "tok set:", bool(tok))
r = g.residual_probe("v1", FLAG)
print("status:", r["status"])
print("body:", r["body"])
print("ok:", r["ok"])
