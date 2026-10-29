#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same ports; wait until analyst login works.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="$VERSION"
case "$VERSION" in
  v0) hp="${PORT_V0_0:-}" ;;
  v1) hp="${PORT_V1_0:-}" ;;
  *) hp="${PORT_V2_0:-}" ;;
esac
if [[ -z "$hp" ]]; then
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 8088 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
fi
ok=0
for _ in $(seq 1 180); do
  if [[ -n "$hp" ]] && python3 - "$hp" <<'PY'
import json, sys, urllib.request
port = sys.argv[1]
url = f"http://127.0.0.1:{port}/api/v1/security/login"
data = json.dumps({"username": "analyst", "password": "analyst-pw",
                   "provider": "db", "refresh": True}).encode()
try:
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
  then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: superset $SVC login not ready (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
