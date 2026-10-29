#!/usr/bin/env bash
# start.sh — real Admidio + MariaDB + DNS/canary/decoy; wait on published :8080.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

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

UP_ARGS=(up -d --no-build)
img="pcbv2-0023-admidio:5.0.6"
[[ "$VERSION" == "v1" ]] && img="pcbv2-0023-admidio:5.0.7"
[[ "$VERSION" == "v2" ]] && img="pcbv2-0023-admidio:5.0.9"
if ! docker image inspect "$img" >/dev/null 2>&1; then
  UP_ARGS=(up -d --build)
fi

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "${UP_ARGS[@]}"; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 >&2 || true
  exit 1
fi

hp=""
ok=0
for i in $(seq 1 420); do
  if [[ $((i % 15)) -eq 0 ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build >/dev/null 2>&1 || true
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/system/login.php" || true)"
    body="$(curl -sS -m 5 "http://127.0.0.1:${hp}/system/login.php" || true)"
    if [[ "$code" == "200" || "$code" == "302" ]] \
       && ! printf '%s' "$body" | grep -qiE 'SQLSTATE|No route to host'; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $VERSION Admidio login not ready (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION Admidio ready on 127.0.0.1:${hp}"
