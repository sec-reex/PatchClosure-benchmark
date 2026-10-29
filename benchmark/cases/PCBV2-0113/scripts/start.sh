#!/usr/bin/env bash
# start.sh — materialize full FreeScout tree on the host, compose up, wait until
# artisan migrate/create-user/seed finish, /login answers, and victim/callback are up.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

tag_for() {
  case "$1" in
    v0) echo "1.8.179" ;;
    v1) echo "1.8.212" ;;
    v2) echo "1.8.213" ;;
    *) echo "1.8.179" ;;
  esac
}

materialize_tree() {
  local tag dest tgz
  tag="$(tag_for "$VERSION")"
  dest="$CASE_DIR/.build_src"
  rm -rf "$dest"
  mkdir -p "$dest"
  if [[ -f "$WORK_DIR/src/artisan" ]]; then
    echo "start: copying fetch_source tree ($WORK_DIR/src) -> .build_src"
    cp -a "$WORK_DIR/src/." "$dest/"
    return 0
  fi
  echo "start: fetching full FreeScout tarball tag=$tag"
  mkdir -p "$WORK_DIR"
  tgz="$WORK_DIR/freescout-${tag}.tar.gz"
  local url="https://github.com/freescout-help-desk/freescout/archive/refs/tags/${tag}.tar.gz"
  local i
  for i in 1 2 3; do
    if curl -fsSL --retry 3 --retry-delay 4 -o "$tgz" "$url"; then
      tar xzf "$tgz" -C "$dest" --strip-components=1
      rm -f "$tgz"
      [[ -f "$dest/artisan" ]] || { echo "start: tarball missing artisan" >&2; return 1; }
      return 0
    fi
    echo "start: tarball retry $i ($url)" >&2
    sleep 8
  done
  echo "start: failed to fetch $url" >&2
  return 1
}

materialize_tree

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" \
   || -z "${PORT_CALLBACK_0:-}" || -z "${PORT_VICTIM_0:-}" ]]; then
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
  printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0}"
  printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
export PCB_FLAG="$RUN_FLAG"

docker network prune -f >/dev/null 2>&1 || true
sleep $((RANDOM % 6))
ok_up=0
for i in 1 2 3 4 5 6 7 8; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
    ok_up=1
    break
  fi
  # compose can return 1 after a create race even if the profile containers exist
  if [[ -n "$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -q "$VERSION" 2>/dev/null || true)" ]]; then
    echo "start: compose up rc!=0 but $VERSION is up; continuing" >&2
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
  ids="$(docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}" || true)"
  if [[ -n "$ids" ]]; then docker rm -f $ids >/dev/null 2>&1 || true; fi
  docker network prune -f >/dev/null 2>&1 || true
  sleep $((4 * i + RANDOM % 5))
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

ok=0
hp=""
for _ in $(seq 1 150); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  vic="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cb="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    ids="$(curl -s --max-time 5 "http://127.0.0.1:${hp}/pcb_ids.txt" || true)"
    vhealth="$(curl -s --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    chealth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/health" || true)"
    if [[ "$code" == "200" || "$code" == "302" ]] && grep -q 'mailbox=' <<<"$ids" \
       && [[ "$vhealth" == "ok" ]] && [[ "$chealth" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: FreeScout $VERSION did not become ready (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 mysql >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 20 victim >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (artisan install complete; victim+callback up)"
