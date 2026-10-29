#!/usr/bin/env bash
# start.sh — boot REAL Apache OFBiz and wait until HTTP :8080 answers.
# Image already contains clone+load-data. Reuse a complete local pcb/ofbiz-real
# tag with --no-build --pull never so start stays inside the 1500s platform timeout.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
START_TS="$(date +%s)"
# Fail ourselves ~2 min before the controller's 1500s kill, with logs.
DEADLINE="$((START_TS + 1380))"

PORTS="$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
out = []
for n in names:
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'PORT_{n}={p}')
            break
print(' '.join(out))
PY
)"
if [[ -n "$PORTS" ]]; then export $PORTS; fi
mkdir -p "$WORK_DIR"
if [[ -n "$PORTS" ]]; then printf '%s\n' $PORTS > "$WORK_DIR/compose.env"; fi
export PCB_FLAG="$RUN_FLAG"
export BUILDX_NO_DEFAULT_ATTESTATIONS=1
export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1

img=""
case "$VERSION" in
  v0) img="pcb/ofbiz-real:v0-pre49070" ;;
  v1) img="pcb/ofbiz-real:v1-18.12.10" ;;
  v2) img="pcb/ofbiz-real:v2-18.12.11" ;;
esac

compose() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"
}

# Complete = tagged image + seed load-data actually finished (not a stub / partial build).
image_complete() {
  local tag="$1" sz=0
  [[ -n "$tag" ]] || return 1
  docker image inspect "$tag" >/dev/null 2>&1 || return 1
  sz="$(docker image inspect -f '{{.Size}}' "$tag" 2>/dev/null || echo 0)"
  if [[ "${sz:-0}" -lt 400000000 ]]; then
    echo "start: $tag size=${sz} too small (incomplete)" >&2
    return 1
  fi
  if docker run --rm --network none --entrypoint /bin/bash "$tag" -lc \
      'test -x /opt/ofbiz/gradlew && test -s /opt/load.log && grep -qiE "Finished the data load|Beginning the Data Load" /opt/load.log'; then
    return 0
  fi
  echo "start: $tag missing load-data marker" >&2
  return 1
}

remain() { echo "$((DEADLINE - $(date +%s)))"; }

img_ok=0
if image_complete "$img"; then
  img_ok=1
  echo "start: complete cached $img (no rebuild)" >&2
else
  echo "start: $img not complete; gradle clone+load-data build required" >&2
fi

up_ok=0
for attempt in 1 2 3; do
  if (( $(date +%s) >= DEADLINE )); then
    echo "start: deadline before compose (try $attempt)" >&2
    break
  fi
  if [[ "$img_ok" == "1" ]]; then
    echo "start: compose up --no-build --pull never (try $attempt, $(remain)s left)" >&2
    set +e
    compose up -d --no-build --pull never
    rc=$?
    set -e
  else
    echo "start: compose build $VERSION then up --no-build (try $attempt, $(remain)s left)" >&2
    set +e
    compose build "$VERSION"
    brc=$?
    if [[ "$brc" == "0" ]] && image_complete "$img"; then
      img_ok=1
      compose up -d --no-build --pull never
      rc=$?
    else
      rc="${brc:-1}"
    fi
    set -e
  fi
  if [[ "${rc:-1}" == "0" ]]; then
    up_ok=1
    break
  fi
  echo "start: compose rc=$rc (try $attempt)" >&2
  compose down --remove-orphans >/dev/null 2>&1 || true
  docker network rm "${COMPOSE_PROJECT_NAME}_default" >/dev/null 2>&1 || true
  if image_complete "$img"; then
    img_ok=1
  fi
  sleep 3
done
if [[ "$up_ok" != "1" ]]; then
  echo "start: compose up failed for $VERSION after 3 tries" >&2
  exit 1
fi

find_cid() {
  local id=""
  id="$(compose ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -z "$id" ]]; then
    id="$(docker ps -aq \
      -f "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
      -f "label=com.docker.compose.service=${VERSION}" 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "$id" ]]; then
    id="$(docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}-${VERSION}" 2>/dev/null | head -1 || true)"
  fi
  printf '%s' "$id"
}

host_http_port() {
  local cid="$1" hp=""
  hp="$(compose port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -z "$hp" || "$hp" == "<no value>" ]]; then
    hp="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$cid" 2>/dev/null || true)"
  fi
  printf '%s' "$hp"
}

# Ready = mapped :8080 returns any HTTP status. Also surface load-data / Tomcat progress.
ok=0
hp=""
restarts=0
i=0
code=""
while (( $(date +%s) < DEADLINE )); do
  i=$((i + 1))
  cid="$(find_cid)"
  if [[ -z "$cid" ]]; then
    if (( i % 10 == 0 )); then
      echo "start: wait $i no container for $VERSION (project=$COMPOSE_PROJECT_NAME left=$(remain)s)" >&2
    fi
    sleep 3
    continue
  fi
  status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
  if [[ "$status" == "exited" || "$status" == "dead" ]]; then
    echo "start: OFBiz $VERSION $status (cid=${cid:0:12}); logs:" >&2
    docker logs --tail 80 "$cid" >&2 || true
    if (( restarts < 2 )); then
      restarts=$((restarts + 1))
      echo "start: restarting $VERSION ($restarts/2)" >&2
      compose up -d --no-build --pull never || true
      sleep 5
      continue
    fi
    exit 1
  fi
  if [[ "$status" == "running" ]]; then
    hp="$(host_http_port "$cid")"
    if [[ -n "$hp" && "$hp" != "<no value>" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
      if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
        ok=1
        break
      fi
    fi
    if (( i % 8 == 0 )); then
      echo "start: wait $i $VERSION running host=${hp:-none} http=${code:-none} left=$(remain)s" >&2
      docker logs --tail 20 "$cid" 2>&1 | grep -E -i \
        'Finished the data load|Beginning the Data Load|EntityDataLoad|pcb-loaddata|Server startup|OFBiz is started|Started in |HttpContainer|Catalina|BUILD SUCCESSFUL|8080|8443|ERROR|Exception' \
        >&2 || docker logs --tail 8 "$cid" >&2 || true
    fi
  fi
  sleep 3
done
if [[ "$ok" != "1" ]]; then
  echo "start: OFBiz $VERSION did not become ready on HTTP 8080 (host=$hp)" >&2
  compose ps -a >&2 || true
  cid="$(find_cid)"
  if [[ -n "$cid" ]]; then
    docker inspect -f 'status={{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' "$cid" >&2 || true
    docker logs --tail 120 "$cid" >&2 || true
  fi
  exit 1
fi
echo "start: $VERSION OFBiz ready on 127.0.0.1:${hp} (http ${code})"
