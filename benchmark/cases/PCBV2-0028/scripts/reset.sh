#!/usr/bin/env bash
# reset.sh — keep the stack (no down --volumes: pip + grid restart is leftover rc=20).
# Clear callback hits and `up --pull never` if a sidecar died.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="${RUN_FLAG:-${PCB_FLAG:-}}"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

host_port() {
  docker compose -p "$COMPOSE_PROJECT_NAME" port "$1" "$2" 2>/dev/null \
    | sed -E 's/.*:([0-9]+)$/\1/' | tr -d '[:space:]' | tail -1 || true
}

_grid_ready() {
  dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://chromium:4444/status', timeout=5).read()" \
    >/dev/null 2>&1 \
  || dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://chromium:4444/wd/hub/status', timeout=5).read()" \
    >/dev/null 2>&1
}

dc up -d --pull never >/dev/null 2>&1 || true

ok=0
hp="" vp="" cp=""
for i in $(seq 1 90); do
  hp="$(host_port "$VERSION" 80)"
  vp="$(host_port victim 8070)"
  cp="$(host_port callback 9000)"
  if [[ -n "$hp" && -n "$vp" && -n "$cp" ]]; then
    curl -sS -m 5 "http://127.0.0.1:${cp}/reset" >/dev/null 2>&1 || true
    acode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login.php" || true)"
    vbody="$(curl -s --max-time 5 "http://127.0.0.1:${vp}/health" || true)"
    cbody="$(curl -s --max-time 5 "http://127.0.0.1:${cp}/health" || true)"
    if [[ "$acode" =~ ^[1-5][0-9][0-9]$ && "$vbody" == *"ok"* && "$cbody" == *"ok"* ]] \
       && _grid_ready; then
      ok=1
      break
    fi
  fi
  if [[ "$i" == "12" || "$i" == "30" ]]; then
    dc up -d --no-deps --pull never chromium victim >/dev/null 2>&1 || true
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: TestLink $VERSION not ready (app=$hp victim=$vp callback=$cp)" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION TestLink ready on 127.0.0.1:${hp} (callback cleared, stack kept)"
