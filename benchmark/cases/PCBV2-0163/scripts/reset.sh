#!/usr/bin/env bash
# reset.sh — do NOT down --volumes (selenium pip + grid restart is leftover rc=20).
# Clear callback hits and wait until app/victim/callback/grid answer.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

_port_of() {
  local svc="$1" cport="$2" hp=""
  case "$svc" in
    v0) hp="${PORT_V0_0:-}";;
    v1) hp="${PORT_V1_0:-}";;
    v2) hp="${PORT_V2_0:-}";;
    victim) hp="${PORT_VICTIM_0:-}";;
    callback) hp="${PORT_CALLBACK_0:-}";;
  esac
  if [[ -n "$hp" ]]; then
    echo "$hp"
    return 0
  fi
  dc port "$svc" "$cport" 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]' || true
}

_grid_ready() {
  dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://browser:4444/status', timeout=5).read()" \
    >/dev/null 2>&1 \
  || dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://browser:4444/wd/hub/status', timeout=5).read()" \
    >/dev/null 2>&1
}

ok=0
app_hp=""
for i in $(seq 1 90); do
  app_hp="$(_port_of "$SVC" 80)"
  vic_hp="$(_port_of victim 8070)"
  cb_hp="$(_port_of callback 9000)"
  if [[ -n "$app_hp" && -n "$vic_hp" && -n "$cb_hp" ]]; then
    curl -sS -m 5 "http://127.0.0.1:${cb_hp}/reset" >/dev/null 2>&1 || true
    if curl -fsS --max-time 5 "http://127.0.0.1:${app_hp}/health" >/dev/null 2>&1 \
       && curl -fsS --max-time 5 "http://127.0.0.1:${vic_hp}/health" >/dev/null 2>&1 \
       && curl -fsS --max-time 5 "http://127.0.0.1:${cb_hp}/health" >/dev/null 2>&1 \
       && _grid_ready; then
      ok=1
      break
    fi
  fi
  if [[ "$i" == "12" || "$i" == "30" ]]; then
    dc up -d --no-deps --pull never victim browser >/dev/null 2>&1 || true
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC did not become ready (host=${app_hp:-none})" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${app_hp} (callback cleared, stack kept)"
