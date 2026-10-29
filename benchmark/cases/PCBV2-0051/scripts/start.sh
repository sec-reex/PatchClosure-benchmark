#!/usr/bin/env bash
# start.sh — official wordpress:php8.2-apache + ASE zip. Wait until wp-login
# answers and /flag/pcb_flag.txt exists (same as compose healthcheck).
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
eval "$(python3 - <<'PY'
import os, re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
for n in names:
    cur = os.environ.get(f'PORT_{n}')
    if cur and cur.isdigit():
        used.add(int(cur))
out = []
for n in names:
    key = f'PORT_{n}'
    if os.environ.get(key):
        continue
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'{key}={p}')
            break
print('\n'.join(out))
PY
)"
{
  printf 'PORT_WP_V0_0=%s\n' "${PORT_WP_V0_0:?}"
  printf 'PORT_WP_V1_0=%s\n' "${PORT_WP_V1_0:?}"
  printf 'PORT_WP_V2_0=%s\n' "${PORT_WP_V2_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_WP_V0_0 PORT_WP_V1_0 PORT_WP_V2_0
export PCB_FLAG="$RUN_FLAG"

# Keep WordPress siteurl in sync with the randomized host port (compose
# interpolates WP_HOST_PORT from the same PORT_WP_V*_0 used in ports:).
case "$VERSION" in
  v0) export WP_HOST_PORT="${PORT_WP_V0_0:-39450}";;
  v1) export WP_HOST_PORT="${PORT_WP_V1_0:-39451}";;
  v2) export WP_HOST_PORT="${PORT_WP_V2_0:-39452}";;
  *) export WP_HOST_PORT="${PORT_WP_V1_0:-39451}";;
esac
printf 'WP_HOST_PORT=%s\n' "$WP_HOST_PORT" >> "$WORK_DIR/compose.env"

mkdir -p "$CASE_DIR/_run"
case "$VERSION" in v0) PVER=7.6.2;; v1) PVER=7.6.3;; v2) PVER=8.8.4;; *) PVER=7.6.2;; esac
ZIP="$CASE_DIR/_run/admin-site-enhancements.zip"
if ! curl -fsSL -o "$ZIP" "https://downloads.wordpress.org/plugin/admin-site-enhancements.${PVER}.zip"; then
  echo "start: wordpress.org ASE ${PVER} zip download failed" >&2
  exit 1
fi

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
  # rebound host ports in case the previous attempt hit a bind conflict
  unset PORT_WP_V0_0 PORT_WP_V1_0 PORT_WP_V2_0
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
  {
    printf 'PORT_WP_V0_0=%s\n' "${PORT_WP_V0_0:?}"
    printf 'PORT_WP_V1_0=%s\n' "${PORT_WP_V1_0:?}"
    printf 'PORT_WP_V2_0=%s\n' "${PORT_WP_V2_0:?}"
  } > "$WORK_DIR/compose.env"
  export PORT_WP_V0_0 PORT_WP_V1_0 PORT_WP_V2_0
  case "$VERSION" in
    v0) export WP_HOST_PORT="${PORT_WP_V0_0}";;
    v1) export WP_HOST_PORT="${PORT_WP_V1_0}";;
    v2) export WP_HOST_PORT="${PORT_WP_V2_0}";;
  esac
  printf 'WP_HOST_PORT=%s\n' "$WP_HOST_PORT" >> "$WORK_DIR/compose.env"
  sleep 5
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 >&2 || true
  exit 1
fi

SVC="wp-${VERSION}"
ok=0
hp=""
for i in $(seq 1 180); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$SVC" 2>/dev/null | head -1)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "start: $SVC exited before ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
      exit 1
    fi
    if [[ "$status" == "running" ]] \
       && docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$SVC" \
            test -f /flag/pcb_flag.txt 2>/dev/null; then
      hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
      if [[ -n "$hp" ]]; then
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/wp-login.php" || true)"
        if [[ "$code" == "200" ]]; then
          ok=1
          break
        fi
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: WordPress $SVC not ready (wp-login + /flag/pcb_flag.txt; host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
printf 'PUBLISHED_PORT=%s\n' "$hp" >> "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${hp} (siteurl port ${WP_HOST_PORT})"
