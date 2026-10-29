#!/usr/bin/env bash
# seed.sh — Plant flag dashboard + passwordless share link in already-running
# DataEase MySQL. Extracted from de_ready.sh::seed_flag_dashboard().
# Assumes containers are already up and healthy. Idempotent (DELETE + INSERT).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi

RESOURCE_ID="${RESOURCE_ID:-777000777}"
MYSQL_PASS="${MYSQL_PASS:-Password123@mysql}"

_mysql() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" exec -T "mysql_${VERSION}" mysql -uroot -p"${MYSQL_PASS}" \
    -e "$1" dataease 2>/dev/null
}

if [[ ! "$FLAG" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "seed: FLAG has unexpected characters" >&2
  exit 1
fi

sql="DELETE FROM data_visualization_info WHERE id='${RESOURCE_ID}';
DELETE FROM xpack_share WHERE resource_id=${RESOURCE_ID};
INSERT INTO data_visualization_info (id,name,pid,org_id,level,node_type,type,canvas_style_data,component_data,status,create_time,create_by,version,delete_flag) VALUES ('${RESOURCE_ID}','${FLAG}','0','1',0,'canvas','dashboard','{}','[]',1,UNIX_TIMESTAMP()*1000,'1',3,0);
INSERT INTO xpack_share (id,creator,time,exp,uuid,pwd,resource_id,oid,type) VALUES (777001,1,UNIX_TIMESTAMP()*1000,0,'flaguuid00000001',NULL,${RESOURCE_ID},1,0);"

for i in $(seq 1 40); do
  _mysql "$sql" 2>&1 || true
  if _mysql "SELECT name FROM data_visualization_info WHERE id='${RESOURCE_ID}';" 2>/dev/null | grep -q "$FLAG" \
     && _mysql "SELECT resource_id FROM xpack_share WHERE resource_id=${RESOURCE_ID};" 2>/dev/null | grep -q "${RESOURCE_ID}"; then
    echo "seed: DataEase flag dashboard planted (${VERSION})"
    exit 0
  fi
  sleep 3
done
echo "seed: DataEase flag dashboard seed failed" >&2
exit 1
