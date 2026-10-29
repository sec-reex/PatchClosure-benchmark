#!/usr/bin/env bash
# start.sh — 启动 compose 并把 RUN_FLAG 注入目标。平台注入 RUN_ID/COMPOSE_PROJECT_NAME/RUN_FLAG/VERSION/WORK_DIR。
# Overlayfs/container-create flakes: persist ports, retry up, treat "already up" as success.
# Readiness is /pcb_driver.php (copied only after c5:install + Express seed).
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
mkdir -p "$WORK_DIR"

if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
eval "$(python3 - <<'PY'
import os, re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
for n in names:
    cur = os.environ.get(f'PORT_{n}')
    if cur and cur.isdigit():
        used.add(int(cur))
out = []
for n in names:
    key = f'PORT_{n}'
    if os.environ.get(key):
        continue
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'{key}={p}')
            break
print('\n'.join(out))
PY
)"
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0:?}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0:?}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

case "$VERSION" in
  v0) img="pcb-concrete:9.4.7"; pin="pcb-0097-v0:9.4.7" ;;
  v1) img="pcb-concrete:9.4.8"; pin="pcb-0097-v1:9.4.8" ;;
  v2) img="pcb-concrete:9.5.1"; pin="pcb-0097-v2:9.5.1" ;;
  *) echo "start: unknown VERSION=$VERSION" >&2; exit 1 ;;
esac
# Platform/OrbStack stop --rmi untags pcb-concrete:* but pin repos keep the layers.
ensure_img() {
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    if docker image inspect "$pin" >/dev/null 2>&1; then
      docker tag "$pin" "$img" || true
    fi
  fi
  if docker image inspect "$img" >/dev/null 2>&1; then
    UP_ARGS=(-d)
  else
    UP_ARGS=(-d --build)
  fi
}
ensure_img

docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker network prune -f >/dev/null 2>&1 || true
sleep $((RANDOM % 5))

ok_up=0
for i in 1 2 3 4 5 6; do
  ensure_img
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up "${UP_ARGS[@]}"; then
    ok_up=1
    break
  fi
  if [[ -n "$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -q "$VERSION" 2>/dev/null || true)" ]]; then
    echo "start: compose up rc!=0 but $VERSION is up; continuing" >&2
    ok_up=1
    break
  fi
  echo "start: compose up retry $i (overlayfs/container-create)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
  ids="$(docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}" || true)"
  if [[ -n "$ids" ]]; then docker rm -f $ids >/dev/null 2>&1 || true; fi
  docker network prune -f >/dev/null 2>&1 || true
  sleep $((6 * i + RANDOM % 5))
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

# c5:install + Express seed run in the entrypoint AFTER apache is already up.
ok=0
hp=""
for _ in $(seq 1 360); do
  status="$(docker inspect -f '{{.State.Status}}' "${COMPOSE_PROJECT_NAME}-${VERSION}-1" 2>/dev/null || echo missing)"
  if [[ "$status" == "exited" || "$status" == "dead" || "$status" == "missing" ]]; then
    echo "start: $VERSION $status during install; re-up" >&2
    ensure_img
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up "${UP_ARGS[@]}" || true
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/pcb_driver.php" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: pcb_driver.php not ready on $VERSION (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION Concrete CMS driver ready on 127.0.0.1:${hp}"
