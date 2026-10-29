#!/usr/bin/env bash
# reset.sh — do NOT down --volumes (mysql re-migrate + victim pip reinstall
# is the leftover rc=20). Clear the in-memory callback and wait until ready.
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

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }
_hostport() { dc port "$1" "$2" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}'; }

ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(_hostport "$VERSION" 80)"
  vic="$(_hostport victim 8070)"
  cb="$(_hostport callback 9000)"
  if [[ -z "$hp" ]]; then
    case "$VERSION" in
      v0) hp="${PORT_V0_0:-}" ;;
      v1) hp="${PORT_V1_0:-}" ;;
      v2) hp="${PORT_V2_0:-}" ;;
    esac
  fi
  vic="${vic:-${PORT_VICTIM_0:-}}"
  cb="${cb:-${PORT_CALLBACK_0:-}}"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]]; then
    curl -sS -m 5 "http://127.0.0.1:${cb}/reset" >/dev/null 2>&1 || true
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    ids="$(curl -s --max-time 5 "http://127.0.0.1:${hp}/pcb_ids.txt" || true)"
    vhealth="$(curl -s --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    chealth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/health" || true)"
    if [[ "$code" == "200" || "$code" == "302" ]] && grep -q 'mailbox=' <<<"$ids" \
       && [[ "$vhealth" == "ok" ]] && [[ "$chealth" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: FreeScout $VERSION did not become ready (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp} (callback cleared, stack kept)"
