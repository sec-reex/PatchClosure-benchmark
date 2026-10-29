#!/bin/sh
# PatchClosure 4-edge driver for keystone6 (CVE pair). The frozen oracle is single-target:
#   oracle.py <base_url> <flag> [original|cursor]   (default "both")
# -> prints {"original":{"verdict":"REACHED|BLOCKED|MISS"},"cursor":{"verdict":...}}
# gate.sh deploys v0/v1/v2 (external) on the compose default ports, exports PCB_FLAG, then runs this
# via its GATE_DRIVER hook. We call the oracle once per live version and assemble the 4 edges into
# the canonical JSON (+ top-level `passed`) that gate.sh's parser consumes.
set -eu
F="${PCB_FLAG:?PCB_FLAG not set}"
# keystone6 compose has no healthcheck, so gate.sh's `up -d --wait` returns before the app serves.
# The oracle probes `{ secrets{ id } }`; the entrypoint seeds the code==PCB_FLAG Secret only AFTER
# GraphQL comes up, so probing on mere HTTP-up raced the seed -> "no records" -> every verdict MISS.
# Wait until the GraphQL secrets list is non-empty (seed complete) before probing.
wait_seeded() {
  for _ in $(seq 1 150); do
    n=$(curl -s -X POST "$1/api/graphql" -H 'content-type: application/json' \
          -d '{"query":"{ secrets { id } }"}' 2>/dev/null | grep -o '"id"' | wc -l)
    [ "$n" -ge 1 ] 2>/dev/null && return 0
    sleep 3
  done
  return 0
}
wait_seeded http://127.0.0.1:41390
wait_seeded http://127.0.0.1:41391
wait_seeded http://127.0.0.1:41392
J0=$(python3 oracle.py http://127.0.0.1:41390 "$F" both 2>/dev/null || echo '{}')
J1=$(python3 oracle.py http://127.0.0.1:41391 "$F" both 2>/dev/null || echo '{}')
J2=$(python3 oracle.py http://127.0.0.1:41392 "$F" both 2>/dev/null || echo '{}')
J0="$J0" J1="$J1" J2="$J2" python3 - <<'PY'
import json, os
def load(x):
    try: return json.loads(x)
    except Exception: return {}
j0, j1, j2 = load(os.environ["J0"]), load(os.environ["J1"]), load(os.environ["J2"])
def verdict(d, k): return (d.get(k) or {}).get("verdict")
seed_v0   = verdict(j0, "original") == "REACHED"   # vulnerable v0: seed exploit reaches flag
seed_v1   = verdict(j1, "original") == "BLOCKED"   # patched v1: seed exploit blocked
resid_v1  = verdict(j1, "cursor")   == "REACHED"   # residual (cursor) still reaches on v1
resid_v2  = verdict(j2, "cursor")   == "BLOCKED"   # fully patched v2: residual blocked
print(json.dumps({
    "original_poc_reaches_flag_on_v0": seed_v0,
    "original_poc_blocked_on_v1":      seed_v1,
    "bypass_poc_reaches_flag_on_v1":   resid_v1,
    "bypass_poc_blocked_on_v2":        resid_v2,
    "passed": bool(seed_v0 and seed_v1 and resid_v1 and resid_v2),
}))
PY
