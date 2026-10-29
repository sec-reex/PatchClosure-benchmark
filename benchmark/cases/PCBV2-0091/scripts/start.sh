#!/usr/bin/env bash
# start.sh — compose up REAL Craft CMS; wait until GraphQL answers on the published host port.
# Do not return after `up -d`: `php craft install` + pcb_setup run in the entrypoint.
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
export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONIOENCODING=utf-8

free_unused_sidecar_nets() {
  # Keep 192.0.0.0/24 + fd00:ec2::/64 (SSRF canary/DNS). Drop unused leftover pcbnets.
  python3 - <<'PY'
import json, subprocess, sys
out = subprocess.check_output(["docker", "network", "ls", "-q"], text=True)
ids = [x.strip() for x in out.split() if x.strip()]
if not ids:
    sys.exit(0)
raw = subprocess.check_output(["docker", "network", "inspect"] + ids, text=True)
wanted = {"192.0.0.0/24", "fd00:ec2::/64"}
for net in json.loads(raw):
    name = net.get("Name") or ""
    if not name.startswith("pcb_"):
        continue
    subs = [c.get("Subnet") for c in (net.get("IPAM") or {}).get("Config") or [] if c.get("Subnet")]
    if not wanted.intersection(subs):
        continue
    if net.get("Containers"):
        continue
    subprocess.run(["docker", "network", "rm", net["Id"]], check=False)
    print(f"start: removed leftover sidecar net {name}", file=sys.stderr)
PY
}

up_ok=0
up_out=""
for i in 1 2 3; do
  if up_out="$(python3 - <<'PY'
import os, subprocess, sys
cmd = [
    "docker", "compose",
    "-p", os.environ["COMPOSE_PROJECT_NAME"],
    "--profile", os.environ["VERSION"],
    "up", "-d", "--build",
]
p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
sys.stdout.write(p.stdout.decode("utf-8", "replace"))
sys.exit(p.returncode)
PY
)"; then
    up_ok=1
    break
  fi
  echo "$up_out" >&2
  if echo "$up_out" | grep -qiE 'Pool overlaps|already in use|address.*overlap|ipv6'; then
    echo "start: IPAM overlap on sidecar net, freeing unused pcb leftovers" >&2
    free_unused_sidecar_nets || true
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --remove-orphans || true
  sleep 5
done
if [[ "$up_ok" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 >&2 || true
  exit 1
fi

# Ready ONLY when GraphQL { ping } returns pong. Apache/php 404 or {"data":null}
# is NOT ready. Short curl -m during install RSTs php -S; Apache stays up.
ok=0
hp=""
for _ in $(seq 1 360); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "start: Craft $VERSION exited before GraphQL was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 120 "$VERSION" >&2 || true
      exit 1
    fi
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      body="$(curl -s -m 20 -X POST "http://127.0.0.1:${hp}/index.php?p=actions/graphql/api" \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer pcb_gql_token_ssrf_ipv6_0001' \
        -d '{"query":"{ ping }"}' 2>/dev/null || true)"
      if printf '%s' "$body" | grep -qE '"ping"[[:space:]]*:[[:space:]]*"pong"'; then
        ok=1
        break
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: Craft $VERSION GraphQL not ready on published :80 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 120 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION Craft GraphQL ready on 127.0.0.1:${hp}"
