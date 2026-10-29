#!/usr/bin/env bash
# start.sh — official calciumion/new-api via compose profile; wait on published :3000 /api/status.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="newapi-${VERSION}"
PY="${PCB_PYTHON:-python3}"

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

free_unused_sidecar_nets() {
  # Keep 11.11.11.0/24 (public attacker) and 172.31.9.0/24 (intranet canary).
  # Drop unused pcb_ leftovers on those pools. Never flatten to a default bridge.
  python3 - <<'PY'
import json, subprocess, sys
want = {"11.11.11.0/24", "172.31.9.0/24"}
out = subprocess.check_output(["docker", "network", "ls", "-q"], text=True)
ids = [x.strip() for x in out.split() if x.strip()]
if not ids:
    sys.exit(0)
raw = subprocess.check_output(["docker", "network", "inspect"] + ids, text=True)
for net in json.loads(raw):
    name = net.get("Name") or ""
    if not name.startswith("pcb_"):
        continue
    subs = [c.get("Subnet") for c in (net.get("IPAM") or {}).get("Config") or [] if c.get("Subnet")]
    if not want.intersection(subs):
        continue
    if net.get("Containers"):
        continue
    subprocess.run(["docker", "network", "rm", net["Id"]], check=False)
    print(f"start: removed leftover sidecar net {name}", file=sys.stderr)
PY
}

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "newapi-${other}" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "newapi-${other}" >/dev/null 2>&1 || true
  fi
done

ok_up=0
up_out=""
for i in 1 2 3; do
  if up_out="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d 2>&1)"; then
    ok_up=1
    break
  fi
  echo "$up_out" >&2
  if echo "$up_out" | grep -qiE 'Pool overlaps|already in use|address.*overlap'; then
    echo "start: IPAM overlap, freeing unused 11.11.11.0/24 / 172.31.9.0/24 pcb leftovers" >&2
    free_unused_sidecar_nets || true
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

hp=""
ok=0
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    body="$(curl -sS --max-time 5 "http://127.0.0.1:${hp}/api/status" || true)"
    if printf '%s' "$body" | grep -q '"success"'; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC never answered /api/status on published :3000 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

if ! "$PY" "$CASE_DIR/poc/driver.py" setup "http://127.0.0.1:${hp}"; then
  echo "start: new-api root/channel/token setup failed on 127.0.0.1:${hp}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp} (official calciumion/new-api, setup done)"
