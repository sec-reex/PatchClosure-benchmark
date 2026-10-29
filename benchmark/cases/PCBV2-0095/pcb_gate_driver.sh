#!/bin/sh
# PatchClosure GATE_DRIVER for dataease (CVE-2024-52295 original -> CVE-2026-57172 residual).
# gate.sh runs this with `sh` (dash) -> POSIX only: NO `declare -A`, NO `set -o pipefail`.
# gate.sh (external) already brought the stack up as project $PROJ == GATE_PROJECT
# (dataease-cve-2026-57172 so the mysql container names match). We wait for each app, seed the
# ${PCB_FLAG} dashboard + passwordless share into MySQL, run the forged-JWT probes via the frozen
# oracle, and print canonical 4-edge JSON (+ passed).
set -u
cd "$(dirname "$0")"

PROJ=dataease-cve-2026-57172          # MUST equal GATE_PROJECT in gate_overrides/PCBV2-0095.env
FLAG="${PCB_FLAG:?PCB_FLAG not set}"
RES=777000777

port_for() { case "$1" in v0) echo 18101;; v1) echo 18123;; v2) echo 18124;; esac; }
myc_for()  { case "$1" in v0) echo mysql_v0;; v1) echo mysql_v1;; v2) echo mysql_v2;; esac; }

wait_up() {  # $1 = profile
  port=$(port_for "$1")
  i=0
  while [ "$i" -lt 60 ]; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/de2api/login/localLogin" 2>/dev/null || echo 000)
    [ -n "$code" ] && [ "$code" != "000" ] && { echo "[driver] $1 up (HTTP $code)" >&2; return 0; }
    i=$((i+1)); sleep 10
  done
  echo "[driver] $1 never came up on :${port}" >&2
  return 0
}

seed() {  # $1 = profile
  myc=$(myc_for "$1")
  docker exec "$PROJ-${myc}-1" mysql -uroot -pPassword123@mysql -e \
    "DELETE FROM data_visualization_info WHERE id='$RES'; DELETE FROM xpack_share WHERE resource_id=$RES;
     INSERT INTO data_visualization_info (id,name,pid,org_id,level,node_type,type,canvas_style_data,component_data,status,create_time,create_by,version,delete_flag) VALUES ('$RES','$FLAG','0','1',0,'canvas','dashboard','{}','[]',1,UNIX_TIMESTAMP()*1000,'1',3,0);
     INSERT INTO xpack_share (id,creator,time,exp,uuid,pwd,resource_id,oid,type) VALUES (777001,1,UNIX_TIMESTAMP()*1000,0,'flaguuid00000001',NULL,$RES,1,0);" \
    dataease 2>/dev/null || true
}

probe() { # $1=profile $2=original|residual -> 'True'/'False'
  port=$(port_for "$1")
  PCB_FLAG="$FLAG" python3 oracle.py "http://127.0.0.1:${port}" "$2" 2>/dev/null \
    | python3 -c "import sys,json
try: print(json.load(sys.stdin)['flag_reached'])
except Exception: print('False')"
}

for p in v0 v1 v2; do wait_up "$p"; seed "$p"; done

V0_ORIG=$(probe v0 original)
V1_ORIG=$(probe v1 original)
V1_RES=$(probe v1 residual)
V2_RES=$(probe v2 residual)

V0_ORIG="$V0_ORIG" V1_ORIG="$V1_ORIG" V1_RES="$V1_RES" V2_RES="$V2_RES" python3 - <<'PYEOF'
import json, os
b = lambda k: os.environ[k] == "True"
v0, v1o, v1r, v2 = b("V0_ORIG"), b("V1_ORIG"), b("V1_RES"), b("V2_RES")
print(json.dumps({
    "original_poc_reaches_flag_on_v0": v0,
    "original_poc_blocked_on_v1": not v1o,
    "bypass_poc_reaches_flag_on_v1": v1r,
    "bypass_blocked_on_v2": not v2,
    "passed": v0 and (not v1o) and v1r and (not v2),
}))
PYEOF
