#!/usr/bin/env bash
# start.sh — materialize full FreeScout tree on the host, compose up, wait until
# artisan migrate/create-user/seed finish and /login answers on the published port.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

tag_for() {
  case "$1" in
    v0) echo "1.8.178" ;;
    v1) echo "1.8.223" ;;
    v2) echo "1.8.224" ;;
    *) echo "1.8.178" ;;
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
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
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
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    ids="$(curl -s --max-time 5 "http://127.0.0.1:${hp}/pcb_ids.txt" || true)"
    if [[ "$code" == "200" || "$code" == "302" ]] && grep -q 'mailbox=' <<<"$ids"; then
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
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (artisan install complete)"
