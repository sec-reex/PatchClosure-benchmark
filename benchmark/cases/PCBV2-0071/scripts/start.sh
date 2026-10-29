#!/usr/bin/env bash
# start.sh — official Open WebUI + Milvus stack; no compose profiles.
# Sets OWUI_IMAGE from VERSION, waits until /health returns 200.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"

case "$VERSION" in
  v0) export OWUI_IMAGE="${IMAGE}:${V0}" ;;
  v1) export OWUI_IMAGE="${IMAGE}:${V1}" ;;
  v2) export OWUI_IMAGE="${IMAGE}:${V2:-0.9.6}" ;;
  *) echo "start: bad VERSION=$VERSION" >&2; exit 30 ;;
esac

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${PORT_OPENWEBUI_0:-}" ]]; then
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
export PORT_OPENWEBUI_0 OWUI_IMAGE
export OWUI_EMBED_CACHE="${OWUI_EMBED_CACHE:-/tmp/pcb0071-embed-cache}"
mkdir -p "$OWUI_EMBED_CACHE"
{
  printf 'OWUI_IMAGE=%s\n' "$OWUI_IMAGE"
  printf 'PORT_OPENWEBUI_0=%s\n' "$PORT_OPENWEBUI_0"
} > "$WORK_DIR/compose.env"
export PCB_FLAG="$RUN_FLAG"

# Sweep failed here mid-pull. Prefer local images; retry pull if missing.
_pull_if_missing() {
  local img="$1"
  if docker image inspect "$img" >/dev/null 2>&1; then
    return 0
  fi
  local i
  for i in 1 2 3; do
    echo "start: docker pull ${img} (attempt ${i})" >&2
    if docker pull "$img"; then
      return 0
    fi
    sleep $((i * 8))
  done
  echo "start: failed to pull ${img}" >&2
  return 1
}
_pull_if_missing "quay.io/coreos/etcd:v3.5.5"
_pull_if_missing "minio/minio:RELEASE.2023-03-20T20-16-18Z"
_pull_if_missing "milvusdb/milvus:v2.4.13"
_pull_if_missing "$OWUI_IMAGE"

docker compose -p "$COMPOSE_PROJECT_NAME" up -d

ok=0
hp=""
for _ in $(seq 1 180); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port openwebui 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/health" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 5
done
if [[ "$ok" != "1" ]]; then
  echo "start: Open WebUI ${OWUI_IMAGE} /health not 200 (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" logs --tail 80 openwebui >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" logs --tail 40 milvus >&2 || true
  exit 1
fi
# Pre-download the local embedding model so verify file/add is not racing HF.
timeout 180 docker compose -p "$COMPOSE_PROJECT_NAME" exec -T openwebui \
  python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')" \
  >/dev/null 2>&1 || echo "start: embedding warmup skipped (verify will load it)" >&2
echo "start: ${OWUI_IMAGE} ready on 127.0.0.1:${hp}"
