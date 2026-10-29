#!/usr/bin/env bash
# start.sh — official wordpress:php8.2-apache + whole js-support-ticket zip.
# Wait until wp-login answers on the published port and /flag/ready exists.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

PORTS="$(python3 - <<'PY'
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
print(' '.join(out))
PY
)"
if [[ -n "$PORTS" ]]; then export $PORTS; fi
mkdir -p "$WORK_DIR"
if [[ -n "$PORTS" ]]; then printf '%s\n' $PORTS > "$WORK_DIR/compose.env"; fi
export PCB_FLAG="$RUN_FLAG"

# Keep WordPress siteurl in sync with the randomized host port (compose
# interpolates WP_HOST_PORT from the same PORT_WP_V*_0 used in ports:).
case "$VERSION" in
  v0) export WP_HOST_PORT="${PORT_WP_V0_0:-39510}";;
  v1) export WP_HOST_PORT="${PORT_WP_V1_0:-39511}";;
  v2) export WP_HOST_PORT="${PORT_WP_V2_0:-39512}";;
  *) export WP_HOST_PORT="${PORT_WP_V1_0:-39511}";;
esac
printf 'WP_HOST_PORT=%s\n' "$WP_HOST_PORT" >> "$WORK_DIR/compose.env"

mkdir -p "$CASE_DIR/_run"
case "$VERSION" in v0) PVER=2.8.1;; v1) PVER=2.8.2;; v2) PVER=2.8.3;; *) PVER=2.8.1;; esac
ZIP="$CASE_DIR/_run/js-support-ticket.zip"
if ! curl -fsSL -o "$ZIP" "https://downloads.wordpress.org/plugin/js-support-ticket.${PVER}.zip"; then
  echo "start: wordpress.org js-support-ticket ${PVER} zip download failed" >&2
  exit 1
fi

docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="wp-${VERSION}"
ok=0
hp=""
for i in $(seq 1 180); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" ps -aq "$SVC" 2>/dev/null | head -1)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "start: $SVC exited before ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
      exit 1
    fi
    if [[ "$status" == "running" ]] \
       && docker compose -p "$COMPOSE_PROJECT_NAME" exec -T "$SVC" \
            test -f /flag/ready 2>/dev/null; then
      hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
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
  echo "start: WordPress $SVC not ready (wp-login + /flag/ready; host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp} (siteurl port ${WP_HOST_PORT})"
