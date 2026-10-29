#!/usr/bin/env bash
# start.sh — official n8nio/n8n + sidecar; wait until published :5678 answers.
# --pull never: local n8nio/n8n + python:3.12-slim tags must already exist.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"

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
  printf 'PORT_SIDECAR_0=%s\n' "${PORT_SIDECAR_0:?}"
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0:?}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0:?}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_SIDECAR_0 PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

# Second tag so a sibling JIT `docker rmi n8nio/n8n:X` does not drop the layers.
ensure_n8n_image() {
  local official="" pin=""
  case "$1" in
    v0) official="n8nio/n8n:2.17.3"; pin="pcb-n8n:2.17.3";;
    v1) official="n8nio/n8n:2.20.6"; pin="pcb-n8n:2.20.6";;
    v2) official="n8nio/n8n:2.20.7"; pin="pcb-n8n:2.20.7";;
    *) return 0;;
  esac
  if docker image inspect "$official" >/dev/null 2>&1; then
    docker tag "$official" "$pin" >/dev/null 2>&1 || true
    return 0
  fi
  if docker image inspect "$pin" >/dev/null 2>&1; then
    docker tag "$pin" "$official"
    echo "start: restored $official from $pin" >&2
    return 0
  fi
  echo "start: pulling $official" >&2
  local i
  for i in 1 2 3 4 5; do
    if docker pull "$official"; then
      docker tag "$official" "$pin"
      return 0
    fi
    echo "start: pull $official retry $i" >&2
    sleep 10
  done
  echo "start: pull $official failed" >&2
  return 1
}

ensure_n8n_image "$VERSION"

ok_up=0
for i in 1 2 3; do
  if dc up -d --pull never; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

hp=""
ok=0
code=""
for n in $(seq 1 150); do
  cid="$(dc ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  status="missing"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
  fi
  if [[ "$status" != "running" ]]; then
    echo "start: $SVC status=$status — re-up ($n)" >&2
    dc up -d --pull never >/dev/null || true
    sleep 3
    continue
  fi
  hp="$(dc port "$SVC" 5678 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    code="${code:-000}"
    if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC not ready on published :5678 (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
# '/' is the SPA: 200 before SQLite/REST exist. gpu1 first --seed then POSTs
# /rest/workflows, gets an empty 200, and r.json() raises (rc 20). Wait for a
# real login JSON body before returning.
if ! python3 - "$hp" <<'PY'
import json, sys, time, urllib.error, urllib.request
hp = sys.argv[1]
base = f"http://127.0.0.1:{hp}"
setup = json.dumps({
    "firstName": "pcb", "lastName": "admin",
    "email": "admin@pcb.local", "password": "Admin12345!",
}).encode()
login = json.dumps({
    "emailOrLdapLoginId": "admin@pcb.local", "password": "Admin12345!",
}).encode()
deadline = time.time() + 180
last = "no attempt"
while time.time() < deadline:
    try:
        urllib.request.urlopen(urllib.request.Request(
            base + "/rest/owner/setup", data=setup, method="POST",
            headers={"Content-Type": "application/json"}), timeout=8).read()
    except Exception:
        pass
    try:
        raw = urllib.request.urlopen(urllib.request.Request(
            base + "/rest/login", data=login, method="POST",
            headers={"Content-Type": "application/json"}), timeout=8).read()
        data = json.loads(raw.decode("utf-8", "replace") or "null")
        if isinstance(data, dict) and data.get("data"):
            sys.exit(0)
        last = f"login json without data: {(raw[:160] or b'<empty>').decode('utf-8', 'replace')}"
    except Exception as e:
        last = str(e)
    time.sleep(2)
print(f"start: REST login not ready: {last}", file=sys.stderr)
sys.exit(1)
PY
then
  echo "start: $SVC HTTP up but /rest/login not JSON-ready" >&2
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
# Persist the published ports actually bound (compose port can differ from the planned value).
sc_act="$(dc port sidecar 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
[[ "$sc_act" =~ ^[0-9]+$ ]] && PORT_SIDECAR_0="$sc_act"
if [[ "$hp" =~ ^[0-9]+$ ]]; then
  case "$VERSION" in
    v0) PORT_V0_0="$hp";;
    v1) PORT_V1_0="$hp";;
    v2) PORT_V2_0="$hp";;
  esac
fi
{
  printf 'PORT_SIDECAR_0=%s\n' "${PORT_SIDECAR_0:?}"
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0:?}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0:?}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0:?}"
} > "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${hp} (http ${code})"
