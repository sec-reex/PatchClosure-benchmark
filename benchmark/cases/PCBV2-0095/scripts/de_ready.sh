#!/usr/bin/env bash
# Wait until official DataEase serves HTTP on :8100, then plant the flag dashboard
# + passwordless share in MySQL. Sourced by start.sh / reset.sh.
# Requires COMPOSE_PROJECT_NAME, VERSION, CASE_DIR, RUN_FLAG.

RESOURCE_ID="${RESOURCE_ID:-777000777}"
MYSQL_PASS="${MYSQL_PASS:-Password123@mysql}"
DE_REGISTRY="${DE_REGISTRY:-registry.cn-qingdao.aliyuncs.com/dataease/dataease}"

de_image_for_version() {
  case "${VERSION:-}" in
    v0) echo "${DE_REGISTRY}:v2.10.1" ;;
    v1) echo "${DE_REGISTRY}:v2.10.23" ;;
    v2) echo "${DE_REGISTRY}:v2.10.24" ;;
    *) echo "de_ready: bad VERSION=${VERSION:-}" >&2; return 1 ;;
  esac
}

_ensure_image() {
  local img="$1" i alt=""
  if docker image inspect "$img" >/dev/null 2>&1; then
    return 0
  fi
  case "$img" in
    mysql:*|redis:*) alt="registry.cn-hangzhou.aliyuncs.com/library/${img}" ;;
  esac
  for i in 1 2 3 4 5; do
    if docker pull "$img"; then
      return 0
    fi
    if [[ -n "$alt" ]] && docker pull "$alt"; then
      docker tag "$alt" "$img"
      return 0
    fi
    echo "de_ready: pull retry $i $img" >&2
    sleep $((6 * i))
  done
  echo "de_ready: docker pull failed: $img" >&2
  return 1
}

ensure_de_images() {
  local de
  de="$(de_image_for_version)" || return 1
  _ensure_image "mysql:8.0" || return 1
  _ensure_image "redis:6.2" || return 1
  _ensure_image "$de" || return 1
}

_dc() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"
}

# Controller stores start stderr[:300]. Keep the real compose error in that window.
_compose_err_one_line() {
  local log="$1" line=""
  line="$(grep -iE 'Error|error|failed|conflict|unhealthy|denied|No such' "$log" 2>/dev/null \
    | grep -viE '^(#[0-9]| Container | Network | Volume | Image )' \
    | tail -3 | tr '\n' ';' | head -c 240 || true)"
  if [[ -z "$line" && -f "$log" ]]; then
    line="$(tail -c 240 "$log" | tr '\n' ' ')"
  fi
  printf '%s' "$line"
}

# One profile at a time. Images must already be local (--pull never) so Aliyun
# re-HEAD / concurrent --rmi cannot fail container-create mid-up.
compose_up_profile() {
  local i log ok cid
  : "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${CASE_DIR:?}"
  log="${WORK_DIR:-/tmp}/compose_up_${VERSION}.log"
  mkdir -p "${WORK_DIR:-/tmp}"
  ensure_de_images || return 1
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile v0 --profile v1 --profile v2 down --volumes --remove-orphans >/dev/null 2>&1 || true

  ok=0
  export COMPOSE_PARALLEL_LIMIT=1
  for i in 1 2 3 4 5; do
    ensure_de_images || true
    if _dc up -d --pull never --no-build >"$log" 2>&1; then
      ok=1
      break
    fi
    cid="$(_dc ps -q "dataease_${VERSION}" 2>/dev/null || true)"
    if [[ -n "$cid" ]]; then
      echo "de_ready: compose up rc!=0 but dataease_${VERSION} exists; continuing" >&2
      ok=1
      break
    fi
    echo "de_ready: compose up retry $i $(_compose_err_one_line "$log")" >>"$log"
    _dc down --volumes --remove-orphans >/dev/null 2>&1 || true
    sleep $((5 * i + RANDOM % 4))
  done
  if [[ "$ok" != "1" ]]; then
    echo "de_ready: compose up failed ${VERSION}: $(_compose_err_one_line "$log")" >&2
    return 1
  fi
  return 0
}

_de_host_port() {
  local hp=""
  case "$VERSION" in
    v0) hp="${PORT_DATAEASE_V0_0:-}";;
    v1) hp="${PORT_DATAEASE_V1_0:-}";;
    v2) hp="${PORT_DATAEASE_V2_0:-}";;
  esac
  if [[ -n "$hp" ]]; then
    echo "$hp"
    return 0
  fi
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" port "dataease_${VERSION}" 8100 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]'
}

wait_dataease_ready() {
  local hp="" code="" i
  for i in $(seq 1 120); do
    hp="$(_de_host_port)"
    if [[ -n "$hp" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://127.0.0.1:${hp}/de2api/login/localLogin" || true)"
      if [[ -n "$code" && "$code" != "000" ]]; then
        echo "$hp"
        return 0
      fi
    fi
    sleep 5
  done
  echo "${hp:-}"
  return 1
}

_mysql() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    exec -T "mysql_${VERSION}" mysql -uroot -p"${MYSQL_PASS}" \
    -e "$1" dataease 2>/dev/null
}

seed_flag_dashboard() {
  local flag="${RUN_FLAG:?}" sql i blob
  if [[ ! "$flag" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "de_ready: RUN_FLAG has unexpected characters" >&2
    return 1
  fi
  sql="DELETE FROM data_visualization_info WHERE id='${RESOURCE_ID}';
DELETE FROM xpack_share WHERE resource_id=${RESOURCE_ID};
INSERT INTO data_visualization_info (id,name,pid,org_id,level,node_type,type,canvas_style_data,component_data,status,create_time,create_by,version,delete_flag) VALUES ('${RESOURCE_ID}','${flag}','0','1',0,'canvas','dashboard','{}','[]',1,UNIX_TIMESTAMP()*1000,'1',3,0);
INSERT INTO xpack_share (id,creator,time,exp,uuid,pwd,resource_id,oid,type) VALUES (777001,1,UNIX_TIMESTAMP()*1000,0,'flaguuid00000001',NULL,${RESOURCE_ID},1,0);"
  for i in $(seq 1 40); do
    blob="$(_mysql "$sql" 2>&1)" || true
    if _mysql "SELECT name FROM data_visualization_info WHERE id='${RESOURCE_ID}';" 2>/dev/null | grep -q "$flag" \
       && _mysql "SELECT resource_id FROM xpack_share WHERE resource_id=${RESOURCE_ID};" 2>/dev/null | grep -q "${RESOURCE_ID}"; then
      return 0
    fi
    sleep 3
  done
  echo "de_ready: seed failed: ${blob:0:400}" >&2
  return 1
}
