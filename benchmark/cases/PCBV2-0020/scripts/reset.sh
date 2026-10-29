#!/usr/bin/env bash
# reset.sh — restore this trial (same compose.env ports; wait until :5678 answers).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="${RUN_FLAG:-${PCB_FLAG:-PCBFLAG_UNSET}}"
dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }
dc down --volumes --remove-orphans >/dev/null 2>&1 || true
dc up -d --pull never
hp=""
ok=0
for n in $(seq 1 90); do
  cid="$(dc ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  status="missing"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
  fi
  if [[ "$status" != "running" ]]; then
    dc up -d --pull never >/dev/null || true
    sleep 3
    continue
  fi
  hp="$(dc port "$VERSION" 5678 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $VERSION not ready on published :5678 (host=${hp:-none})" >&2
  dc ps >&2 || true
  exit 1
fi
if ! python3 - "$hp" <<'PY'
import json, sys, time, urllib.request
hp = sys.argv[1]
base = f"http://127.0.0.1:{hp}"
setup = json.dumps({
    "firstName": "pcb", "lastName": "admin",
    "email": "admin@pcb.local", "password": "Admin12345!",
}).encode()
login = json.dumps({
    "emailOrLdapLoginId": "admin@pcb.local", "password": "Admin12345!",
}).encode()
deadline = time.time() + 180
while time.time() < deadline:
    try:
        urllib.request.urlopen(urllib.request.Request(
            base + "/rest/owner/setup", data=setup, method="POST",
            headers={"Content-Type": "application/json"}), timeout=8).read()
    except Exception:
        pass
    try:
        raw = urllib.request.urlopen(urllib.request.Request(
            base + "/rest/login", data=login, method="POST",
            headers={"Content-Type": "application/json"}), timeout=8).read()
        data = json.loads(raw.decode("utf-8", "replace") or "null")
        if isinstance(data, dict) and data.get("data"):
            sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PY
then
  echo "reset: $VERSION HTTP up but /rest/login not JSON-ready" >&2
  dc ps >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp}"
