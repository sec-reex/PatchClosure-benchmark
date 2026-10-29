#!/usr/bin/env bash
# run_gate.sh for dataease-cve-2026-57172 — sequential per-profile driver for
# tools/run_baseline.py (mirrors the construction gate.sh: one profile up at a
# time, seed the ${PCB_FLAG} dashboard + passwordless share, forged-JWT probes).
# Prints the standard gate JSON at the end (parsed by run_baseline.py).
#   original (CVE-2024-52295, X-DE-TOKEN 83d923...) reaches @v0, blocked @v1
#   residual (CVE-2026-57172, X-DE-LINK-TOKEN link-pwd-fit2cloud) reaches @v1, blocked @v2
set -euo pipefail
cd "$(dirname "$0")"

PROJ=dataease-cve-2026-57172
FLAG="${PCB_FLAG:-PCB_FLAG_de57172_a7f3c9e21b}"
RES=777000777

declare -A PORT=( [v0]=18101 [v1]=18123 [v2]=18124 )
declare -A MYC=( [v0]=mysql_v0 [v1]=mysql_v1 [v2]=mysql_v2 )

wait_up() {
  local port=${PORT[$1]}
  for i in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/de2api/login/localLogin" 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      echo "[run_gate] $1 up (HTTP $code)" >&2
      return 0
    fi
    sleep 10
  done
  echo "[run_gate] $1 never came up on :${port}" >&2
  return 1
}

seed() {
  docker exec "$PROJ-${MYC[$1]}-1" mysql -uroot -pPassword123@mysql -e \
    "DELETE FROM data_visualization_info WHERE id='$RES'; DELETE FROM xpack_share WHERE resource_id=$RES;
     INSERT INTO data_visualization_info (id,name,pid,org_id,level,node_type,type,canvas_style_data,component_data,status,create_time,create_by,version,delete_flag) VALUES ('$RES','$FLAG','0','1',0,'canvas','dashboard','{}','[]',1,UNIX_TIMESTAMP()*1000,'1',3,0);
     INSERT INTO xpack_share (id,creator,time,exp,uuid,pwd,resource_id,oid,type) VALUES (777001,1,UNIX_TIMESTAMP()*1000,0,'flaguuid00000001',NULL,$RES,1,0);" \
    dataease 2>/dev/null
}

probe() { # $1=profile $2=original|residual -> prints 'True'/'False'
  local port=${PORT[$1]}
  local out
  out=$(PCB_FLAG="$FLAG" python3 oracle.py "http://127.0.0.1:${port}" "$2" 2>/dev/null || true)
  printf '%s' "$out" | python3 -c "import sys,json;
try: print(json.load(sys.stdin)['flag_reached'])
except Exception: print('False')"
}

echo "[run_gate] ensure stack up (all profiles; run_baseline already started them)" >&2
docker compose -p "$PROJ" --profile v0 --profile v1 --profile v2 up -d >/dev/null 2>&1 || true

for p in v0 v1 v2; do
  if wait_up "$p"; then
    seed "$p"
  fi
done

V0_ORIG=$(probe v0 original)
V1_ORIG=$(probe v1 original)
V1_RES=$(probe v1 residual)
V2_RES=$(probe v2 residual)

PCB_FLAG="$FLAG" python3 - "$V0_ORIG" "$V1_ORIG" "$V1_RES" "$V2_RES" <<'PYEOF'
import json, sys
v0, v1o, v1r, v2 = (x == 'True' for x in sys.argv[1:5])
gate = {
    "original_poc_reaches_flag_on_v0": v0,
    "original_poc_blocked_on_v1": not v1o,
    "bypass_poc_reaches_flag_on_v1": v1r,
    "bypass_blocked_on_v2": not v2,
    "passed": v0 and (not v1o) and v1r and (not v2),
}
print(json.dumps(gate, indent=2))
PYEOF

docker compose -p "$PROJ" --profile v0 --profile v1 --profile v2 down -v >/dev/null 2>&1 || true
