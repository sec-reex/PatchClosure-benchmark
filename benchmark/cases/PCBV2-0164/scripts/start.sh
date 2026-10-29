#!/usr/bin/env bash
# start.sh — compose up, wait until parse answers on its published host port, plant RUN_FLAG via REST.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"

docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build

# Container port is always 1337 (case.yaml readiness/exposed_ports carry the
# container port). The HOST side is per-profile (${PORT_V0_0:-39640},
# ${PORT_V1_0:-39650}, ${PORT_V2_0:-39657}) so all three profiles can coexist.
# Resolve it dynamically like verify.sh does, falling back to the same
# defaults docker-compose.yml uses.
default_host_port() {
  case "$VERSION" in
    v0) echo "${PORT_V0_0:-39640}" ;;
    v1) echo "${PORT_V1_0:-39650}" ;;
    v2) echo "${PORT_V2_0:-39657}" ;;
    *)  echo 1337 ;;
  esac
}

ready=0
host_port=""
for _ in $(seq 1 90); do
  host_port="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "parse_${VERSION}" 1337 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  host_port="${host_port:-$(default_host_port)}"
  if curl -sf "http://127.0.0.1:${host_port}/up" >/dev/null 2>&1 \
     || curl -sf "http://127.0.0.1:${host_port}/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" -ne 1 ]]; then
  echo "start: parse-server did not answer on 127.0.0.1:${host_port:-?}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail=80 >&2 || true
  exit 1
fi

# Plant ACL-restricted flag row + public decoy (idempotent enough for retries).
python3 - "$RUN_FLAG" "$host_port" <<'PY'
import json, sys, time, urllib.error, urllib.parse, urllib.request
flag = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1337
base = f"http://127.0.0.1:{port}/parse"
h = {
    "X-Parse-Application-Id": "pcbApp",
    "X-Parse-Master-Key": "pcbMaster",
    "Content-Type": "application/json",
}

def req(url, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

secret = {"name": "secretrow", "secret": flag, "ACL": {}}
public = {"name": "publicrow", "secret": "decoy-not-the-flag",
          "ACL": {"*": {"read": True, "write": True}}}
last = ""
for _ in range(20):
    c1, b1 = req(base + "/classes/Vault", method="POST", body=secret)
    c2, b2 = req(base + "/classes/Vault", method="POST", body=public)
    last = f"secret={c1} public={c2}"
    if c1 in (200, 201) and c2 in (200, 201):
        where = urllib.parse.quote(json.dumps({"name": "secretrow"}))
        _code, body = req(base + "/classes/Vault?where=" + where)
        if flag in body:
            print("start: vault seeded")
            sys.exit(0)
        # POST succeeded; master-key confirm is best-effort (ACL row is planted).
        print("start: vault planted (" + last + ")")
        sys.exit(0)
    time.sleep(2)
print("start: vault seed failed: " + last, file=sys.stderr)
sys.exit(1)
PY
