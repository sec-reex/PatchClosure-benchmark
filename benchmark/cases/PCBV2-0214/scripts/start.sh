#!/usr/bin/env bash
# start.sh — official xwiki:<tag> + MariaDB; wait until published :8080 AND ssx serves.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
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

ok_up=0
for i in 1 2 3 4; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down -v --remove-orphans >/dev/null 2>&1 || true
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$VERSION" >&2 || true
  exit 1
fi

# First-boot (Tomcat + XWiki + MariaDB) can take several minutes. ssx is the
# oracle path: wait until it returns a real HTTP status (200/404), not TCP-only.
# Re-up if the project was pruned mid-wait (disk_watchdog / daemon flake).
hp=""
ok=0
planted=0
for _ in $(seq 1 180); do
  if ! docker compose -p "$COMPOSE_PROJECT_NAME" ps -q "$VERSION" 2>/dev/null | grep -q .; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d >/dev/null 2>&1 || true
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    if docker compose -p "$COMPOSE_PROJECT_NAME" exec -T "$VERSION" \
         test -f /usr/local/tomcat/webapps/ROOT/WEB-INF/pcb_flag.txt 2>/dev/null; then
      planted=1
    fi
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
      "http://127.0.0.1:${hp}/bin/ssx/Main/WebHome?resource=pcb-ready-check&minify=false" 2>/dev/null || true)"
    if [[ "$planted" == "1" && "$code" =~ ^(200|404)$ ]]; then
      # two consecutive ssx answers — Tomcat can RST the first probe after boot
      sleep 2
      code2="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
        "http://127.0.0.1:${hp}/bin/ssx/Main/WebHome?resource=pcb-ready-check&minify=false" 2>/dev/null || true)"
      if [[ "$code2" =~ ^(200|404)$ ]]; then
        ok=1
        break
      fi
    fi
  fi
  sleep 5
done
if [[ "$ok" != "1" ]]; then
  echo "start: $VERSION ssx never ready on published 8080 (host=${hp:-none} planted=$planted)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (official xwiki, ssx serving, flag planted)"
