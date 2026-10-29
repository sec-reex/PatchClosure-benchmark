#!/usr/bin/env bash
# start.sh — compose up REAL SuiteCRM; wait until silent install finished (login page).
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
  # Reuse the tagged SuiteCRM image when present; --build rebuilds ~2GB every run.
  UP_ARGS=(up -d)
  img="pcbv2-0204-suitecrm:7.14.5"
  [[ "$VERSION" == "v1" ]] && img="pcbv2-0204-suitecrm:7.15.0"
  [[ "$VERSION" == "v2" ]] && img="pcbv2-0204-suitecrm:7.15.1"
  if docker image inspect "$img" >/dev/null 2>&1; then
    UP_ARGS+=( --no-build --pull never )
  else
    UP_ARGS+=( --build --pull never )
  fi
  if up_out="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "${UP_ARGS[@]}" 2>&1)"; then
    n="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq 2>/dev/null | wc -l | tr -d ' ')"
    echo "start: compose up ok (containers=${n})" >&2
    if [[ "${n:-0}" != "0" ]]; then
      up_ok=1
      break
    fi
    echo "start: compose up returned 0 but no containers; retry $i" >&2
  else
    echo "$up_out" >&2
    echo "start: compose up retry $i" >&2
  fi
  sleep 8
done
if [[ "$up_ok" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 >&2 || true
  exit 1
fi

ok=0
hp=""
restarts=0
for i in $(seq 1 420); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -z "$cid" && $((i % 15)) -eq 0 ]]; then
    echo "start: no $VERSION container; re-issuing compose up --no-build" >&2
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build --pull never >/dev/null 2>&1 || true
  fi
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "start: SuiteCRM $VERSION $status before login was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
      if (( restarts < 2 )); then
        restarts=$((restarts + 1))
        echo "start: compose up --no-build ($restarts/2)" >&2
        docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build --pull never || true
        sleep 5
        continue
      fi
      exit 1
    fi
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$VERSION" test -f /tmp/pcb_ready 2>/dev/null; then
        body="$(curl -sS -m 8 "http://127.0.0.1:${hp}/index.php?module=Users&action=Login" || true)"
        if printf '%s' "$body" | grep -q 'user_name' && ! printf '%s' "$body" | grep -qi 'SilentInstall'; then
          ok=1
          break
        fi
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: SuiteCRM $VERSION login page not ready on published :80 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION SuiteCRM login ready on 127.0.0.1:${hp}"
