#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=HTTP body contains RUN_FLAG (exfil via keras load_weights)
# 10=blocked/no flag  20=env  30=args
#
# Effect channel = JSON body from /exploit (kernel bytes after load_weights).
# Flag is planted at start from PCB_FLAG; judge uses RUN_FLAG so wrong/stale
# overrides (channel has the real planted flag, RUN_FLAG is the override) fail.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
JUDGE="$RUN_FLAG"
mkdir -p "$WORK_DIR"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

PORT=""
for _ in $(seq 1 60); do
  PORT="$(dc port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${PORT}/health" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:3000 (need --profile)" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2026-1669: HDF5 EXTERNAL dataset -> /flag.txt
  QMODE=seed
else
  # CVE-2026-12480: Virtual Dataset over /app/secret.h5 (V1 only checks external)
  QMODE=residual
fi

BODY="$(curl -sS -m 60 "http://127.0.0.1:${PORT}/exploit?mode=${QMODE}")" || {
  echo "verify: curl failed" >&2
  exit 20
}
echo "mode=${MODE#--} body=${BODY:0:400}"
if [[ -n "$JUDGE" && "$BODY" == *"$JUDGE"* ]]; then
  exit 0
fi
exit 10
