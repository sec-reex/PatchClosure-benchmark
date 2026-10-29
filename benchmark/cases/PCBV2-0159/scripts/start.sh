#!/usr/bin/env bash
# start.sh — official openremote/manager stack; no compose profiles.
# Pre-pull official tags (retries) then `up --pull never` so Hub congestion
# during compose does not fail the sweep the way 1.21.0/1.22.0 did.
# Sets MANAGER_VERSION from VERSION, waits until manager / or /auth answers
# and admin token grant works, then plants RUN_FLAG at /flag (no trailing newline).
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"

if [[ "$VERSION" == "v0" ]]; then
  export MANAGER_VERSION="${V0}"
elif [[ "$VERSION" == "v2" ]]; then
  export MANAGER_VERSION="${V2}"
else
  export MANAGER_VERSION="${V1}"
fi

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${MGR_PORT:-}" || -z "${COLLECTOR_PORT:-}" ]]; then
  eval "$(python3 - <<'PY'
import random
used = set()
def p():
    while True:
        n = random.randint(20000, 59999)
        if n not in used:
            used.add(n)
            return n
print("MGR_PORT=%d" % p())
print("COLLECTOR_PORT=%d" % p())
PY
)"
fi
export MGR_PORT COLLECTOR_PORT MANAGER_VERSION
{
  printf 'MANAGER_VERSION=%s\n' "$MANAGER_VERSION"
  printf 'MGR_PORT=%s\n' "$MGR_PORT"
  printf 'COLLECTOR_PORT=%s\n' "$COLLECTOR_PORT"
} > "$WORK_DIR/compose.env"
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" "$@"; }

ensure_image() {
  local img="$1"
  if docker image inspect "$img" >/dev/null 2>&1; then
    return 0
  fi
  echo "start: pulling $img" >&2
  local i
  for i in 1 2 3 4 5; do
    if docker pull "$img"; then
      return 0
    fi
    echo "start: pull $img retry $i" >&2
    sleep 10
  done
  echo "start: pull $img failed" >&2
  return 1
}

ensure_image "openremote/manager:${MANAGER_VERSION}"
ensure_image "openremote/postgresql:latest-slim"
ensure_image "openremote/keycloak:23.0.7.6"
ensure_image "python:3.12-alpine"

# Postgres initdb (Timescale) shuts the server down after the first health
# pass. Wait until it stays healthy so Keycloak's first JDBC connect works.
ok_up=0
dc up -d --pull never --no-deps postgresql collector || true
stable=0
for _ in $(seq 1 90); do
  pg="$(dc ps -aq postgresql 2>/dev/null | head -1 || true)"
  h=""
  if [[ -n "$pg" ]]; then
    h="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$pg" 2>/dev/null || true)"
  fi
  if [[ "$h" == "healthy" ]]; then
    stable=$((stable + 1))
    if [[ "$stable" -ge 20 ]]; then
      break
    fi
  else
    stable=0
  fi
  sleep 2
done
sleep 5
for i in 1 2 3 4 5; do
  if dc up -d --pull never --remove-orphans; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  dc logs --tail 80 keycloak >&2 || true
  dc logs --tail 40 postgresql >&2 || true
  sleep 12
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for manager ${MANAGER_VERSION}" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 manager >&2 || true
  dc logs --tail 80 keycloak >&2 || true
  dc logs --tail 40 postgresql >&2 || true
  exit 1
fi

ok=0
hp=""
for n in $(seq 1 240); do
  cid="$(dc ps -aq manager 2>/dev/null | head -1 || true)"
  status="missing"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
  fi
  if [[ "$status" == "created" ]]; then
    # Waiting on keycloak health; do not bounce the stack.
    sleep 3
    continue
  fi
  if [[ "$status" != "running" ]]; then
    echo "start: manager status=$status — re-up ($n)" >&2
    dc up -d --pull never >/dev/null 2>&1 || true
    sleep 3
    continue
  fi
  hp="$(dc port manager 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    root_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    auth_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/auth/" || true)"
    if [[ "$root_code" =~ ^[1-5][0-9][0-9]$ || "$auth_code" =~ ^[1-5][0-9][0-9]$ ]]; then
      tok="$(curl -sS --max-time 15 -d 'grant_type=password&client_id=openremote&username=admin&password=secret' \
        "http://127.0.0.1:${hp}/auth/realms/master/protocol/openid-connect/token" 2>/dev/null || true)"
      if grep -q 'access_token' <<<"$tok"; then
        ok=1
        break
      fi
    fi
  fi
  sleep 3
done
if [[ "$ok" != "1" ]]; then
  echo "start: manager ${MANAGER_VERSION} did not answer / or /auth with a working token (host=$hp)" >&2
  dc ps >&2 || true
  dc logs --tail 80 manager >&2 || true
  dc logs --tail 40 keycloak >&2 || true
  dc logs --tail 40 postgresql >&2 || true
  exit 1
fi

# Plant per-run canary. No trailing newline — it breaks the KNX OOB URI.
if ! dc exec -T -u 0 manager \
  sh -c "printf '%s' \"$RUN_FLAG\" > /flag"; then
  echo "start: could not plant /flag in manager" >&2
  exit 1
fi
coll_act="$(dc port collector 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
[[ "$coll_act" =~ ^[0-9]+$ ]] && COLLECTOR_PORT="$coll_act"
[[ "$hp" =~ ^[0-9]+$ ]] && MGR_PORT="$hp"
{
  printf 'MANAGER_VERSION=%s\n' "$MANAGER_VERSION"
  printf 'MGR_PORT=%s\n' "$MGR_PORT"
  printf 'COLLECTOR_PORT=%s\n' "$COLLECTOR_PORT"
} > "$WORK_DIR/compose.env"
echo "start: manager ${MANAGER_VERSION} ready on 127.0.0.1:${hp} (collector :${COLLECTOR_PORT})"
