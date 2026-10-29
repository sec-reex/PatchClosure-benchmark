#!/usr/bin/env bash
# start.sh — compose up Camaleon profile only; wait until published :3000 answers.
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
  printf 'PORT_APP_V0_LOCAL_0=%s\n' "${PORT_APP_V0_LOCAL_0:?}"
  printf 'PORT_APP_V1_LOCAL_0=%s\n' "${PORT_APP_V1_LOCAL_0:?}"
  printf 'PORT_APP_V1_S3_0=%s\n' "${PORT_APP_V1_S3_0:?}"
  printf 'PORT_APP_V2_S3_0=%s\n' "${PORT_APP_V2_S3_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_APP_V0_LOCAL_0 PORT_APP_V1_LOCAL_0 PORT_APP_V1_S3_0 PORT_APP_V2_S3_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

case "$VERSION" in
  v0) SVCS="app_v0_local" ;;
  v1) SVCS="app_v1_local app_v1_s3" ;;
  v2) SVCS="app_v2_s3" ;;
  *) echo "start: unknown VERSION=$VERSION" >&2; exit 1 ;;
esac

ok_up=0
for i in 1 2 3; do
  if dc up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 >&2 || true
  exit 1
fi

wait_http() {
  local svc="$1"
  local hp="" ok=0 code=""
  for _ in $(seq 1 180); do
    cid="$(dc ps -aq "$svc" 2>/dev/null | head -1 || true)"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
      if [[ "$status" == "exited" ]]; then
        echo "start: $svc exited before Rails was ready" >&2
        dc logs --tail 160 "$svc" >&2 || true
        return 1
      fi
    fi
    hp="$(dc port "$svc" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:${hp}/admin/login" || echo 000)"
      if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
        echo "start: $svc ready on 127.0.0.1:${hp} (http ${code})"
        return 0
      fi
    fi
    sleep 2
  done
  echo "start: $svc not ready on published :3000 (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 160 "$svc" >&2 || true
  return 1
}

for svc in $SVCS; do
  wait_http "$svc" || exit 1
done
