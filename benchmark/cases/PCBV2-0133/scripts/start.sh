#!/usr/bin/env bash
# start.sh — official Quay Keycloak + http-echo canary; wait until realm answers.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

# Randomize only Keycloak host ports. Attacker stays on 40052 so it matches
# realm-export.json redirectUris and the probe redirect_uri.
PORTS="$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
names = [n for n in names if 'ATTACKER' not in n]
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
export PORT_ATTACKER_0="${PORT_ATTACKER_0:-40052}"
mkdir -p "$WORK_DIR"
{
  [[ -n "$PORTS" ]] && printf '%s\n' $PORTS
  printf 'PORT_ATTACKER_0=%s\n' "$PORT_ATTACKER_0"
} > "$WORK_DIR/compose.env"
export PCB_FLAG="$RUN_FLAG"

docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="$VERSION"
ok=0
hp=""
for _ in $(seq 1 180); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/realms/pcb" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: Keycloak $SVC did not import realm pcb (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

acode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT_ATTACKER_0}/" || true)"
if [[ "$acode" != "200" ]]; then
  echo "start: attacker sidecar not answering on :${PORT_ATTACKER_0} (http $acode)" >&2
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp} (realm pcb); attacker :${PORT_ATTACKER_0}"
