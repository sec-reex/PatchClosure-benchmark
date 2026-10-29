#!/usr/bin/env bash
# start.sh — compose up Dubbo provider; persist compose.env; wait PROVIDER_READY.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"

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
  printf 'PLANTED_FLAG=%s\n' "$RUN_FLAG"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

# Build ONLY this version (no extra client Maven image). Then up without --build
# so a cache-miss rebuild cannot race the running JVM.
ok_build=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" build "$SVC"; then
    ok_build=1
    break
  fi
  echo "start: compose build retry $i" >&2
  sleep 8
done
if [[ "$ok_build" != "1" ]]; then
  echo "start: compose build failed for $SVC" >&2
  exit 1
fi

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

# Do NOT raw-TCP-probe :20880. Dubbo 2.7.6 treats an empty connect/close as a
# decode error, closes the Netty channel, then interrupts main (v0 seed miss).
_cid() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$SVC" 2>/dev/null | head -1
}
_status() {
  local id
  id="$(_cid)"
  if [[ -z "$id" ]]; then
    echo missing
    return
  fi
  docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null || echo missing
}
_ready_log() {
  local id
  id="$(_cid)"
  if [[ -n "$id" ]] && docker logs --tail 80 "$id" 2>/dev/null | grep -q 'PROVIDER_READY'; then
    return 0
  fi
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --no-log-prefix "$SVC" 2>/dev/null \
    | grep -q 'PROVIDER_READY'
}

hp=""
exported=0
for _ in $(seq 1 90); do
  status="$(_status)"
  if [[ "$status" == "exited" || "$status" == "dead" ]]; then
    cid="$(_cid)"
    if [[ -n "$cid" ]]; then
      docker start "$cid" >/dev/null 2>&1 || true
    else
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build >/dev/null 2>&1 || true
    fi
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 20880 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -z "$hp" ]]; then
    cid="$(_cid)"
    if [[ -n "$cid" ]]; then
      hp="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "20880/tcp") 0).HostPort}}' "$cid" 2>/dev/null || true)"
    fi
  fi
  if _ready_log; then
    exported=1
    break
  fi
  sleep 2
done
if [[ "$exported" != "1" || -z "$hp" ]]; then
  echo "start: $SVC never printed PROVIDER_READY (host=${hp:-none} status=$(_status))" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  cid="$(_cid)"
  [[ -n "$cid" ]] && docker logs --tail 160 "$cid" >&2 || true
  exit 1
fi
# export() returns before Netty's boss thread is fully accepting; require a
# sustained 'running' window (first snapshot used to miss a later OOM/exit).
sleep 4
stable=0
for _ in $(seq 1 20); do
  status="$(_status)"
  if [[ "$status" == "running" ]]; then
    stable=$((stable + 1))
    if [[ "$stable" -ge 5 ]]; then
      break
    fi
  else
    stable=0
    cid="$(_cid)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      if [[ -n "$cid" ]]; then
        docker start "$cid" >/dev/null 2>&1 || true
      else
        docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build >/dev/null 2>&1 || true
      fi
    fi
  fi
  sleep 2
done
if [[ "$stable" -lt 5 ]]; then
  echo "start: $SVC not stably running after PROVIDER_READY (status=$(_status))" >&2
  cid="$(_cid)"
  [[ -n "$cid" ]] && docker logs --tail 160 "$cid" >&2 || true
  exit 1
fi
printf 'PUBLISHED_PORT=%s\n' "$hp" >> "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${hp} (PROVIDER_READY)"
