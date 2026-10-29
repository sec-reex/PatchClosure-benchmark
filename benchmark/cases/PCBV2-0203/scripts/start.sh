#!/usr/bin/env bash
# start.sh — compose up REAL struts2-core file-upload WAR; wait until /index.jsp is 200
# (WAR exploded). Platform 404-as-ready would race the explode.
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
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" ]]; then
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
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"
export VERSION

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
case "$VERSION" in
  v0) hp="${PORT_V0_0}" ;;
  v1) hp="${PORT_V1_0}" ;;
  v2) hp="${PORT_V2_0}" ;;
esac
ok=0
for _ in $(seq 1 90); do
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:${hp}/index.jsp" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC never answered GET /index.jsp on 127.0.0.1:${hp:-none}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -a >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

case "$VERSION" in
  v0) PORT_V0_0="$hp" ;;
  v1) PORT_V1_0="$hp" ;;
  v2) PORT_V2_0="$hp" ;;
esac
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
} > "$WORK_DIR/compose.env"

echo "start: $SVC ready on 127.0.0.1:${hp} (struts GET /index.jsp)"
