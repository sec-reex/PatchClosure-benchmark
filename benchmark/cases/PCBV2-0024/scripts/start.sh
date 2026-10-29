#!/usr/bin/env bash
# start.sh — compose up real ComfyUI + victim/callback; plant PCB_FLAG; wait on published ports.
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
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0:?}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0:?}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0:?}"
  printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0:?}"
  printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_VICTIM_0 PORT_CALLBACK_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

ok_up=0
for i in 1 2 3; do
  if dc up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

hp=""; vic=""; cb=""; ok=0
for _ in $(seq 1 150); do
  cid="$(dc ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "start: $SVC exited before ready" >&2
      dc logs --tail 160 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(dc port "$SVC" 8188 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  vic="$(dc port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cb="$(dc port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]]; then
    a="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    v="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/health" || true)"
    if [[ "$a" == "200" && "$v" == "200" && "$c" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: app/victim/callback not ready (app=${hp:-none} victim=${vic:-none} callback=${cb:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  dc logs --tail 40 victim >&2 || true
  dc logs --tail 20 callback >&2 || true
  exit 1
fi

echo "=== cert proof: ComfyUI git HEAD + main.py/server.py from /app (cloned repo, not a stub) ==="
dc exec -T "$SVC" sh -c 'cd /app && git rev-parse HEAD && git log -1 --oneline && wc -l main.py server.py && echo "--- main.py head ---" && head -n 8 main.py'
echo "start: $SVC ready on 127.0.0.1:${hp}; victim :${vic}; callback :${cb}"
