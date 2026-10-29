#!/usr/bin/env bash
# start.sh — official apache/superset overlay + analytics postgres.
# Wait until the real /api/v1/security/login answers (bootstrap finished).
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
case "$VERSION" in
  v0) TAG=4.0.1; hp="${PORT_V0_0:-}" ;;
  v1) TAG=4.0.2; hp="${PORT_V1_0:-}" ;;
  *) TAG=5.0.0; hp="${PORT_V2_0:-}" ;;
esac
if docker image inspect "pcb-superset-denylist:${TAG}" >/dev/null 2>&1; then
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d
else
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build
fi

SVC="$VERSION"
if [[ -z "$hp" ]]; then
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 8088 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
fi
if [[ -z "$hp" ]]; then
  echo "start: no host port for $SVC (compose.env missing PORT_${VERSION^^}_0)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -a >&2 || true
  exit 1
fi

ok=0
for _ in $(seq 1 180); do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps --status running -q "$SVC" 2>/dev/null | grep -q .; then
    if python3 - "$hp" <<'PY'
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
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: superset $SVC login not ready (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -a >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp}"
