#!/usr/bin/env bash
# start.sh — official DataEase via compose profile; wait on :8100 and plant flag dashboard.
# Images are pulled first; compose up uses --pull never and retries create flakes.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/scripts/de_ready.sh"

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${PORT_DATAEASE_V0_0:-}" || -z "${PORT_DATAEASE_V1_0:-}" || -z "${PORT_DATAEASE_V2_0:-}" ]]; then
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
  printf 'PORT_DATAEASE_V0_0=%s\n' "${PORT_DATAEASE_V0_0}"
  printf 'PORT_DATAEASE_V1_0=%s\n' "${PORT_DATAEASE_V1_0}"
  printf 'PORT_DATAEASE_V2_0=%s\n' "${PORT_DATAEASE_V2_0}"
} > "$WORK_DIR/compose.env"
export PORT_DATAEASE_V0_0 PORT_DATAEASE_V1_0 PORT_DATAEASE_V2_0
export PCB_FLAG="$RUN_FLAG"

if ! compose_up_profile; then
  echo "start: compose up failed for profile $VERSION" >&2
  _dc logs --tail 40 "dataease_${VERSION}" >&2 || true
  exit 1
fi

hp=""
if ! hp="$(wait_dataease_ready)"; then
  echo "start: $VERSION /de2api/login/localLogin never answered (host=${hp:-none})" >&2
  _dc ps >&2 || true
  _dc logs --tail 80 "dataease_${VERSION}" >&2 || true
  exit 1
fi
if ! seed_flag_dashboard; then
  echo "start: flag dashboard seed failed" >&2
  _dc logs --tail 40 "dataease_${VERSION}" >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (flag dashboard planted)"
