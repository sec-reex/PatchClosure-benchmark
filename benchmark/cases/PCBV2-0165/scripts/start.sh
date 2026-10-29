#!/usr/bin/env bash
# start.sh — official dpage/pgadmin4; wait until /login answers; plant RUN_FLAG.
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
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" ]]; then
  eval "$(python3 - <<'PY'
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
print('\n'.join(out))
PY
)"
fi
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="$VERSION"
ok=0
hp=""
for _ in $(seq 1 120); do
  if ! docker compose -p "$COMPOSE_PROJECT_NAME" ps -q "$SVC" 2>/dev/null | grep -q .; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d >/dev/null 2>&1 || true
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: pgAdmin $SVC did not answer /login (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

# Plant the per-run flag inside the official image (env + file). verify reads
# this planted value only after an unauthenticated route body actually runs.
docker compose -p "$COMPOSE_PROJECT_NAME" exec -T "$SVC" \
  sh -c "printf '%s\n' \"$RUN_FLAG\" > /tmp/pcb_flag" || {
  echo "start: could not plant /tmp/pcb_flag in $SVC" >&2
  exit 1
}
echo "start: $SVC ready on 127.0.0.1:${hp}"
