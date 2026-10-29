#!/usr/bin/env bash
# verify.sh --seed|--residual — dubbo serializer-switch RCE（CVE-2020-1948 seed /
# native-hessian id-10 residual）。效果=server 日志出现 RUN_FLAG。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

PLANTED_FLAG=""
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
# Look for the platform's RUN_FLAG (wrong/stale inject a different one). Never
# re-plant the container with that value.
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

APP_PORT="${PUBLISHED_PORT:-}"
if [[ -z "$APP_PORT" ]]; then
  case "$VERSION" in
    v0) APP_PORT="${PORT_V0_0:-}";;
    v1) APP_PORT="${PORT_V1_0:-}";;
    v2) APP_PORT="${PORT_V2_0:-}";;
  esac
fi
if [[ -z "$APP_PORT" ]]; then
  for _ in $(seq 1 30); do
    APP_PORT="$(dc port "$VERSION" 20880 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
    if [[ -n "$APP_PORT" ]]; then
      break
    fi
    sleep 1
  done
fi
if [[ -z "$APP_PORT" ]]; then
  echo "verify: cannot resolve ${VERSION}:20880 (need --profile / compose.env)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"

# Do not raw-TCP-probe the Dubbo port (2.7.6 closes the channel).
# If the JVM exited, docker start uses the original planted flag (not RUN_FLAG).
_cid() { dc ps -aq "$VERSION" 2>/dev/null | head -1; }
ready=0
for _ in $(seq 1 30); do
  cid="$(_cid)"
  status="missing"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
  fi
  if [[ "$status" == "running" ]]; then
    ready=1
    break
  fi
  if [[ "$status" == "exited" || "$status" == "dead" ]]; then
    docker start "$cid" >/dev/null 2>&1 || true
  elif [[ "$status" == "restarting" ]]; then
    sleep 2
    continue
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  echo "verify: ${VERSION} container not running (published :${APP_PORT})" >&2
  dc logs --tail 80 "$VERSION" >&2 || true
  exit 20
fi

if [[ "$MODE" == "--seed" ]]; then
  CAND='{"id": "cve-2020-1948-hessian2-arg-seed", "serialization": "hessian2"}'
else
  CAND='{"id": "residual-native-hessian-10", "serialization": "native-hessian"}'
fi

OUT="$(printf '%s' "$CAND" | "$PY" "$CASE_DIR/poc/seed_exec.py" /dev/stdin "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
raw = sys.argv[1]
d = None
for line in raw.splitlines()[::-1]:
    line = line.strip()
    if line.startswith('{'):
        try:
            d = json.loads(line)
            break
        except Exception:
            pass
if d is None:
    try:
        d = json.loads(raw)
    except Exception:
        sys.exit(20)
if d.get('env_error'):
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
