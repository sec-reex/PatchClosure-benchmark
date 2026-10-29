#!/bin/sh
# PatchClosure 4-edge driver for arcadedb (CVE pair). The frozen oracle is single-target and
# self-seeds + waits for readiness:
#   oracle.py <base_url> <original|residual>  -> prints {"detected": bool, ...}
#   ("detected" == a read-only token successfully mutated the schema == authz bypass reproduced)
# gate.sh deploys v0/v1/v2 (external) on compose default ports, then runs this via GATE_DRIVER.
# 4 probes assemble the 4 edges + a top-level `passed`.
set -eu
det() {  # $1=base $2=payload -> prints "True"/"False"
  python3 - "$(python3 oracle.py "$1" "$2" 2>/dev/null || echo '{}')" <<'PY'
import json, sys
try: d = json.loads(sys.argv[1])
except Exception: d = {}
print("True" if d.get("detected") is True else "False")
PY
}
S_V0=$(det http://127.0.0.1:24801 original)   # vulnerable v0: seed detected
S_V1=$(det http://127.0.0.1:24802 original)   # patched v1: seed NOT detected (blocked)
R_V1=$(det http://127.0.0.1:24802 residual)   # residual still detected on v1
R_V2=$(det http://127.0.0.1:24803 residual)   # fully patched v2: residual blocked
S_V0="$S_V0" S_V1="$S_V1" R_V1="$R_V1" R_V2="$R_V2" python3 - <<'PY'
import json, os
b = lambda k: os.environ[k] == "True"
seed_v0, seed_v1_det, resid_v1, resid_v2_det = b("S_V0"), b("S_V1"), b("R_V1"), b("R_V2")
seed_v1  = not seed_v1_det   # blocked == NOT detected
resid_v2 = not resid_v2_det
print(json.dumps({
    "original_poc_reaches_flag_on_v0": seed_v0,
    "original_poc_blocked_on_v1":      seed_v1,
    "bypass_poc_reaches_flag_on_v1":   resid_v1,
    "bypass_poc_blocked_on_v2":        resid_v2,
    "passed": bool(seed_v0 and seed_v1 and resid_v1 and resid_v2),
}))
PY
