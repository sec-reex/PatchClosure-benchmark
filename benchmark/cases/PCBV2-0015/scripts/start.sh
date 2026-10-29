#!/usr/bin/env bash
# start.sh — compose up postcss@pinned + watchdog; wait until GET /health and
# watchdog baseline (ok_streak=3) are ready so ReDoS can release PCB_FLAG.
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
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" || -z "${PORT_WATCHDOG_0:-}" ]]; then
  eval "$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
keys = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+)(?::-?[^}]*)?\}', text)))
used = set()
out = []
for n in keys:
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
  printf 'PORT_WATCHDOG_0=%s\n' "${PORT_WATCHDOG_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_WATCHDOG_0
export PCB_FLAG="$RUN_FLAG"
export VERSION

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

hp=""
ok=0
for _ in $(seq 1 60); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 3000 2>/dev/null | awk -F: 'NF{print $NF; exit}' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:${hp}/health" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC never answered GET /health on published :3000 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

wd=""
wd_ok=0
for _ in $(seq 1 40); do
  wd="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port watchdog 8888 2>/dev/null | awk -F: 'NF{print $NF; exit}' | tr -d '[:space:]' || true)"
  if [[ -n "$wd" ]]; then
    st="$(curl -sS -m 5 "http://127.0.0.1:${wd}/status" 2>/dev/null || true)"
    if printf '%s' "$st" | grep -q '"ok_streak": 3'; then
      wd_ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$wd_ok" != "1" ]]; then
  echo "start: watchdog baseline not ready (host=${wd:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 watchdog >&2 || true
  exit 1
fi

# Persist the probed host ports so verify.sh does not need `docker compose port`.
case "$VERSION" in
  v0) PORT_V0_0="$hp" ;;
  v1) PORT_V1_0="$hp" ;;
  v2) PORT_V2_0="$hp" ;;
esac
PORT_WATCHDOG_0="$wd"
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
  printf 'PORT_WATCHDOG_0=%s\n' "${PORT_WATCHDOG_0}"
} > "$WORK_DIR/compose.env"
printf '%s' "$RUN_FLAG" > "$WORK_DIR/planted.flag"

echo "start: $SVC ready on 127.0.0.1:${hp} (postcss GET /health); watchdog :${wd}"
