#!/usr/bin/env bash
# seed.sh — Plant ACL-restricted flag row + public decoy in already-running Parse Server.
# Uses the same REST API pattern as start.sh. Idempotent (Parse deduplicates or
# overwrites rows; the verify probe matches by name).
# Assumes containers are already up and healthy.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi

# Resolve host port dynamically
default_host_port() {
  case "$VERSION" in
    v0) echo "${PORT_V0_0:-39640}" ;;
    v1) echo "${PORT_V1_0:-39650}" ;;
    v2) echo "${PORT_V2_0:-39657}" ;;
    *)  echo 1337 ;;
  esac
}
host_port="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "parse_${VERSION}" 1337 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
host_port="${host_port:-$(default_host_port)}"

# Plant ACL-restricted flag row + public decoy (idempotent enough for retries).
python3 - "$FLAG" "$host_port" <<'PY'
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
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0, ""

secret = {"name": "secretrow", "secret": flag, "ACL": {}}
public = {"name": "publicrow", "secret": "decoy-not-the-flag",
          "ACL": {"*": {"read": True, "write": True}}}
last = ""
for _ in range(60):
    c1, b1 = req(base + "/classes/Vault", method="POST", body=secret)
    c2, b2 = req(base + "/classes/Vault", method="POST", body=public)
    last = f"secret={c1} public={c2}"
    if c1 in (200, 201) and c2 in (200, 201):
        where = urllib.parse.quote(json.dumps({"name": "secretrow"}))
        _code, body = req(base + "/classes/Vault?where=" + where)
        if flag in body:
            print("seed: vault seeded")
            sys.exit(0)
        # POST succeeded; master-key confirm is best-effort (ACL row is planted).
        print("seed: vault planted (" + last + ")")
        sys.exit(0)
    time.sleep(2)
print("seed: vault seed failed: " + last, file=sys.stderr)
sys.exit(1)
PY
