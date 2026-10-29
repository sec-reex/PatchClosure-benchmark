#!/usr/bin/env bash
# start.sh — official gogs/gogs; keep the container up through install restart.
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
# Persist the planted canary (start-time RUN_FLAG). verify must not replant
# the submitted wrong/stale token via compose up.
printf 'PCB_PLANTED_FLAG=%s\nPCB_FLAG=%s\n' "$RUN_FLAG" "$RUN_FLAG" >> "$WORK_DIR/compose.env"
export PCB_FLAG="$RUN_FLAG"

compose() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"
}

compose up -d --pull never

SVC="$VERSION"
case "$VERSION" in
  v0) HP="${PORT_V0_0:-}" ;;
  v1) HP="${PORT_V1_0:-}" ;;
  *) HP="${PORT_V2_0:-}" ;;
esac

keep_up() {
  local cid estate
  cid="$(compose ps -q "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -z "$cid" ]]; then
    compose up -d --pull never >/dev/null || true
    return
  fi
  estate="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
  if [[ "$estate" != "running" ]]; then
    echo "start: $SVC state=$estate, bringing back up" >&2
    compose logs --tail 40 "$SVC" >&2 || true
    compose up -d --pull never >/dev/null || true
  fi
}

ok=0
for _ in $(seq 1 90); do
  keep_up
  [[ -n "$HP" ]] || HP="$(compose port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$HP" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${HP}/" || true)"
    if [[ "$code" =~ ^(200|301|302|303)$ ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: gogs $SVC HTTP not ready (host=$HP)" >&2
  compose ps -a >&2 || true
  compose logs --tail 80 "$SVC" >&2 || true
  exit 20
fi

if ! python3 "$CASE_DIR/scripts/init_gogs.py" "$HP"; then
  echo "start: init_gogs failed (host=$HP)" >&2
  compose ps -a >&2 || true
  compose logs --tail 80 "$SVC" >&2 || true
  # install restarts gogs; bring the container back and retry once
  keep_up
  sleep 5
  if ! python3 "$CASE_DIR/scripts/init_gogs.py" "$HP"; then
    echo "start: init_gogs retry failed" >&2
    compose ps -a >&2 || true
    compose logs --tail 80 "$SVC" >&2 || true
    exit 20
  fi
fi

ok=0
for _ in $(seq 1 60); do
  keep_up
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${HP}/user/login" || true)"
  if [[ "$code" == "200" ]]; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: gogs $SVC /user/login not ready after install (host=$HP)" >&2
  compose ps -a >&2 || true
  compose logs --tail 80 "$SVC" >&2 || true
  exit 20
fi
# Let the post-install process finish binding before the first verify.
sleep 3
echo "start: $SVC ready on 127.0.0.1:${HP}"
