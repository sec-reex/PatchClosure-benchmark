#!/usr/bin/env bash
# start.sh — official dpage/pgadmin4 + postgres; wait until /login answers.
# Pre-pull official tags (retries) then `up --pull never` so a congested Hub
# Head during compose does not fail the sweep the way 9.15/9.16 did.
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

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

ensure_image() {
  local img="$1"
  if docker image inspect "$img" >/dev/null 2>&1; then
    return 0
  fi
  echo "start: pulling $img" >&2
  local i
  for i in 1 2 3 4 5; do
    if docker pull "$img"; then
      return 0
    fi
    echo "start: pull $img retry $i" >&2
    sleep 10
  done
  echo "start: pull $img failed" >&2
  return 1
}

case "$VERSION" in
  v0) ensure_image "dpage/pgadmin4:9.15" ;;
  v1) ensure_image "dpage/pgadmin4:9.16" ;;
  v2) ensure_image "dpage/pgadmin4:9.17" ;;
  *) echo "start: bad VERSION=$VERSION" >&2; exit 30 ;;
esac
ensure_image "postgres:16-alpine"

ok_up=0
for i in 1 2 3; do
  if dc up -d --pull never; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 "$VERSION" >&2 || true
  dc logs --tail 40 "pg_${VERSION}" >&2 || true
  exit 1
fi

SVC="$VERSION"
PG="pg_${VERSION}"
ok=0
hp=""
for _ in $(seq 1 120); do
  if ! dc ps -q "$SVC" 2>/dev/null | grep -q .; then
    dc up -d --pull never >/dev/null 2>&1 || true
  fi
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    if [[ "$code" == "200" ]]; then
      secret="$(dc exec -T "$PG" \
        psql -U postgres -tAc "SELECT secret FROM pcb_secret LIMIT 1" 2>/dev/null \
        | tr -d '\r' | head -1 | tr -d '[:space:]' || true)"
      if grep -Fq "$RUN_FLAG" <<<"$secret"; then
        ok=1
        break
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: pgAdmin $SVC did not become ready (host=$hp)" >&2
  dc ps >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  dc logs --tail 40 "$PG" >&2 || true
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp}"
