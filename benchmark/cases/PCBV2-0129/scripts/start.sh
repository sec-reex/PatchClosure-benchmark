#!/usr/bin/env bash
# start.sh — official jenkins/jenkins via compose profile; wait until init hooks finish.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/scripts/jenkins_ready.sh"

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" ]]; then
  eval "$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
out = []
for n in names:
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'PORT_{n}={p}')
            break
print('\n'.join(out))
PY
)"
fi
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

hp=""
for attempt in 1 2 3; do
  ok_up=0
  for i in 1 2 3; do
    if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
      ok_up=1
      break
    fi
    echo "start: compose up retry $i" >&2
    sleep 8
  done
  if [[ "$ok_up" != "1" ]]; then
    echo "start: compose up failed for profile $VERSION (attempt $attempt)" >&2
    continue
  fi
  if hp="$(wait_jenkins_ready "$VERSION")"; then
    echo "start: $VERSION ready on 127.0.0.1:${hp} (init.groovy.d done, pcbReveal live)"
    exit 0
  fi
  echo "start: $VERSION not ready (host=${hp:-none}), recycle attempt $attempt" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$VERSION" >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --force-recreate "$VERSION" >/dev/null 2>&1 || true
done
echo "start: $VERSION pcbReveal never ready (host=${hp:-none})" >&2
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
exit 1
