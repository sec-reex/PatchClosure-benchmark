#!/bin/sh
# PatchClosure 4-edge driver for astro-cloudflare SSRF (CVE pair). The frozen oracle runs ONE
# profile per call and reports both markers:
#   oracle.py --profile {v0,v1,v2} --base-url <url> [--wait]
#   -> prints {"original_reaches_canary": bool, "residual_reaches_canary": bool, ...}
# gate.sh deploys v0/v1/v2 (external; canary/allowed sidecars auto-up) on compose default app ports,
# then runs this via GATE_DRIVER. 3 invocations assemble the 4 edges + top-level `passed`.
set -eu
probe() {  # $1=profile $2=base -> prints "<orig> <resid>" as True/False
  python3 - "$(python3 oracle.py --profile "$1" --base-url "$2" --wait 2>/dev/null || echo '{}')" <<'PY'
import json, sys
try: d = json.loads(sys.argv[1])
except Exception: d = {}
print(("True" if d.get("original_reaches_canary") is True else "False") + " " +
      ("True" if d.get("residual_reaches_canary") is True else "False"))
PY
}
set -- $(probe v0 http://127.0.0.1:4310); V0_ORIG=$1
set -- $(probe v1 http://127.0.0.1:4311); V1_ORIG=$1; V1_RESID=$2
set -- $(probe v2 http://127.0.0.1:4312); V2_RESID=$2
V0_ORIG="$V0_ORIG" V1_ORIG="$V1_ORIG" V1_RESID="$V1_RESID" V2_RESID="$V2_RESID" python3 - <<'PY'
import json, os
b = lambda k: os.environ[k] == "True"
seed_v0  = b("V0_ORIG")            # vulnerable v0: original SSRF reaches canary
seed_v1  = not b("V1_ORIG")        # patched v1: original blocked
resid_v1 = b("V1_RESID")           # residual (sibling path) still reaches on v1
resid_v2 = not b("V2_RESID")       # fully patched v2: residual blocked
print(json.dumps({
    "original_poc_reaches_flag_on_v0": seed_v0,
    "original_poc_blocked_on_v1":      seed_v1,
    "bypass_poc_reaches_flag_on_v1":   resid_v1,
    "bypass_poc_blocked_on_v2":        resid_v2,
    "passed": bool(seed_v0 and seed_v1 and resid_v1 and resid_v2),
}))
PY
