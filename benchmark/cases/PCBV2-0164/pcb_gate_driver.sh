#!/bin/sh
# PatchClosure driver for parse-server pg SQLi. The oracle's --seed plants the flag row via the
# Parse REST API, but parse_v* has no healthcheck, so gate.sh's `up -d --wait` returns once the DB
# is healthy while the parse Node app is still connecting -> seed(v0) POSTs into a not-ready app ->
# no row -> original leak on v0 fails (seed_v0_reaches=false). The parse image has no curl/wget, so
# wait from the host (gate.sh runs this on the remote where the ports are published), THEN run the
# oracle's seed+gate+v2check in one process. Oracle prints {"seed":..,"gate":{..edges..,passed},..}
# and gate.sh's wrapper-lift pulls out["gate"].
set -u
F="${PCB_FLAG:?PCB_FLAG not set}"
wait_health() {  # $1 = base (host:port), parse mounted at /parse; /parse/health is open (no appId)
  for _ in $(seq 1 100); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$1/parse/health" 2>/dev/null || echo 000)
    [ "$code" = "200" ] && return 0
    sleep 3
  done
  return 0
}
wait_health http://127.0.0.1:39640
wait_health http://127.0.0.1:39641
wait_health http://127.0.0.1:39642
PCB_FLAG="$F" python3 oracle.py --seed --profiles v0 v1 v2 --gate --v2check
