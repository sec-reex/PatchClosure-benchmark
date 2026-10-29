#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same ports; wait until login answers.
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
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="frappe-$VERSION"
SITE="${VERSION}.local"
ok=0
hp=""
for _ in $(seq 1 240); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
      -H "Host: ${SITE}" \
      -d 'usr=Administrator&pwd=admin' \
      "http://127.0.0.1:${hp}/api/method/login" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: Frappe $SVC did not answer login (host=$hp site=$SITE)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 120 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
