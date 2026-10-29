#!/usr/bin/env bash
# run_gate.sh — REAL-APP sequential 4-way gate for open-webui-cve-2026-54019.
# Boots REAL Open WebUI (official image) + REAL Milvus (multitenancy) per version,
# seeds a victim private KB with ${PCB_FLAG}, drives the attacker over EXTERNAL HTTP.
# 8GB Docker RAM cannot host 3 Milvus stacks at once, so versions run sequentially
# with a fresh Milvus (`down -v`) between them.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
: "${PCB_FLAG:?set PCB_FLAG to the per-run authz canary token}"
BASE="http://127.0.0.1:39581"
declare -A IMG=(
  [v0]="ghcr.io/open-webui/open-webui:0.8.12"
  [v1]="ghcr.io/open-webui/open-webui:0.9.0"
  [v2]="ghcr.io/open-webui/open-webui:0.9.6"
)
RES="$HERE/results"; mkdir -p "$RES"

wait_health() {
  for i in $(seq 1 120); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health" 2>/dev/null || true)
    [ "$code" = "200" ] && return 0
    sleep 5
  done
  return 1
}

for v in v0 v1 v2; do
  echo "================ $v : ${IMG[$v]} ================"
  OWUI_IMAGE="${IMG[$v]}" docker compose up -d 2>&1 | tail -5
  if wait_health; then
    echo "$v: openwebui healthy, running orchestration"
    PCB_FLAG="$PCB_FLAG" python3 orchestrate.py --base "$BASE" --version "$v" \
      > "$RES/$v.json" 2> "$RES/$v.err" && echo "$v: orchestrate OK" || {
        echo "$v: orchestrate FAILED"; cat "$RES/$v.err"; }
  else
    echo "$v: openwebui NEVER healthy"; docker compose logs openwebui 2>&1 | tail -60 > "$RES/$v.err"
  fi
  OWUI_IMAGE="${IMG[$v]}" docker compose down -v 2>&1 | tail -3
done
echo "ALL_VERSIONS_DONE"
