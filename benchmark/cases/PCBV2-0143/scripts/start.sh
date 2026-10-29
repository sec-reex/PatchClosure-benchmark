#!/usr/bin/env bash
# start.sh — compose up real Majordomo 2 CGI under Apache; inject RUN_FLAG as PCB_FLAG.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
mkdir -p "$WORK_DIR"
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
if [[ -n "$PORTS" ]]; then
  # shellcheck disable=SC2086
  export $PORTS
  printf '%s\n' $PORTS > "$WORK_DIR/pcb_ports.env"
fi
export PCB_FLAG="$RUN_FLAG"
export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONIOENCODING=utf-8
# Platform runner uses subprocess text=True (strict UTF-8). Majordomo/apt/perl
# build logs can contain latin-1 (0xe9) and crash start with rc=25.
up_ok=0
for i in 1 2 3; do
  if python3 - <<'PY'
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
  then
    up_ok=1
    break
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --remove-orphans || true
  sleep 8
done
if [[ "$up_ok" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$VERSION" >&2 || true
  exit 1
fi

ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
      "http://127.0.0.1:${hp}/cgi-bin/mj_wwwusr?domain=lists.pcb.test&func=help&extra=overview" || true)"
    if [[ "$code" == "200" ]]; then
      echo "start: Majordomo 2 $VERSION ready on :$hp (help CGI http $code)"
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: Majordomo 2 $VERSION help CGI did not answer (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
