#!/usr/bin/env bash
# start.sh — COPY full pheditor tag into .build_src, compose up, wait until Apache serves pheditor.php.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

tag_for() {
  case "$1" in
    v0) echo "2.0.3" ;;
    v1) echo "2.0.5" ;;
    v2) echo "2.0.6" ;;
    *) echo "" ;;
  esac
}

TAG="$(tag_for "$VERSION")"
[[ -n "$TAG" ]] || { echo "start: unknown VERSION=$VERSION" >&2; exit 1; }

# Platform fetch_source --dest is $WORK_DIR/src; manual dest may be $WORK_DIR itself.
SRC=""
if [[ -f "$WORK_DIR/src/pheditor.php" ]]; then
  SRC="$WORK_DIR/src"
elif [[ -f "$WORK_DIR/pheditor.php" ]]; then
  SRC="$WORK_DIR"
else
  echo "start: missing pheditor.php under $WORK_DIR/src or $WORK_DIR (fetch_source first)" >&2
  exit 1
fi
rm -rf "$CASE_DIR/.build_src"
mkdir -p "$CASE_DIR/.build_src"
cp -a "$SRC/." "$CASE_DIR/.build_src/"
rm -f "$CASE_DIR/.build_src/compose.env"
[[ -f "$CASE_DIR/.build_src/pheditor.php" ]] || { echo "start: .build_src missing pheditor.php" >&2; exit 1; }

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
text = open("docker-compose.yml").read()
names = sorted(set(re.findall(r"\$\{PORT_([A-Za-z0-9_]+):-", text)))
used = set()
out = []
for n in names:
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f"PORT_{n}={p}")
            break
print("\n".join(out))
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
for _ in $(seq 1 60); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/pheditor/pheditor.php" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: pheditor $VERSION did not serve /pheditor/pheditor.php (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION (pheditor $TAG) ready on 127.0.0.1:${hp}/pheditor/pheditor.php"
