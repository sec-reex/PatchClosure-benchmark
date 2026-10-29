#!/usr/bin/env bash
# start.sh — compose up WordPress+plugin; wait until published :80 /wp-login.php answers.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="wp-${VERSION}"

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

# Stage wp-cli + the already-fetched plugin zip so boot does not depend on
# raw.githubusercontent.com / wordpress.org (trial-2 v0 was dying mid-entrypoint).
mkdir -p "$CASE_DIR/_run"
if [[ ! -s "$CASE_DIR/_run/wp-cli.phar" ]]; then
  curl -fsSL -o "$CASE_DIR/_run/wp-cli.phar" \
    https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    || echo "start: wp-cli predownload failed (entrypoint will retry)" >&2
fi
rm -f "$CASE_DIR/_run/fileorganizer.zip"
SRC="${WORK_DIR}/src"
if [[ -d "$SRC/fileorganizer" ]]; then
  (cd "$SRC" && zip -qr "$CASE_DIR/_run/fileorganizer.zip" fileorganizer) \
    || echo "start: could not pack fetched plugin" >&2
elif [[ -f "$SRC/fileorganizer.php" ]]; then
  (cd "$SRC" && zip -qr "$CASE_DIR/_run/fileorganizer.zip" .) \
    || echo "start: could not pack fetched plugin" >&2
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

wp_cid() {
  docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}-${SVC}" | head -1
}

wp_port() {
  local cid hp
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    printf '%s' "$hp"
    return 0
  fi
  cid="$(wp_cid)"
  if [[ -n "$cid" ]]; then
    docker inspect -f '{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' "$cid" 2>/dev/null | tr -d '[:space:]' || true
  fi
}

dump_wp() {
  echo "start: docker ps for ${COMPOSE_PROJECT_NAME}" >&2
  docker ps -a --filter "name=${COMPOSE_PROJECT_NAME}" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' >&2 || true
  dc logs --tail 200 "$SVC" >&2 || true
}

wait_wp() {
  local hp="" code="" cid="" status=""
  for _ in $(seq 1 150); do
    cid="$(wp_cid)"
    if [[ -n "$cid" ]]; then
      seen_cid=1
      status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
      if [[ "$status" == "exited" ]]; then
        echo "start: $SVC exited (cid=$cid)" >&2
        dump_wp
        return 2
      fi
    elif [[ "${seen_cid:-0}" == "1" ]]; then
      echo "start: $SVC container disappeared after start" >&2
      dump_wp
      return 2
    fi
    hp="$(wp_port)"
    if [[ -n "$hp" && "$hp" != "<no value>" ]]; then
      code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/wp-login.php" || echo 000)"
      if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
        echo "start: $SVC ready on 127.0.0.1:${hp} (http ${code})"
        return 0
      fi
    fi
    sleep 2
  done
  echo "start: $SVC not ready on published :80 /wp-login.php (host=${hp:-none})" >&2
  dump_wp
  return 1
}

ok_up=0
for i in 1 2 3; do
  if dc up -d; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dump_wp
  exit 1
fi

rc=0
wait_wp || rc=$?
if [[ "$rc" == "2" ]]; then
  echo "start: recreating $SVC after unexpected exit" >&2
  dc up -d --force-recreate "$SVC" || true
  rc=0
  wait_wp || rc=$?
fi
if [[ "$rc" != "0" ]]; then
  echo "start: WordPress $SVC never became ready" >&2
  exit 1
fi
