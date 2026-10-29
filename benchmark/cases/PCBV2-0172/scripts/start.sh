#!/usr/bin/env bash
# start.sh — compose up REAL Pimcore; wait until admin login answers AFTER
# silent pimcore-install. Do not return after `up -d`.
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

up_ok=0
up_out=""
for i in 1 2 3; do
  if up_out="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build 2>&1)"; then
    up_ok=1
    break
  fi
  echo "$up_out" >&2
  echo "start: compose up retry $i" >&2
  sleep 5
done
if [[ "$up_ok" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 >&2 || true
  exit 1
fi

ok=0
hp=""
for _ in $(seq 1 300); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "start: Pimcore $VERSION exited before admin was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$VERSION" >&2 || true
      exit 1
    fi
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      login="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${hp}/admin/login" || true)"
      cidf="$(curl -sS -m 5 "http://127.0.0.1:${hp}/pcb_class_id.txt" || true)"
      if [[ "$login" == "200" || "$login" == "302" ]] && printf '%s' "$cidf" | grep -qE '^[0-9]+$'; then
        ok=1
        break
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: Pimcore $VERSION admin not ready on published :80 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION Pimcore admin ready on 127.0.0.1:${hp}"
