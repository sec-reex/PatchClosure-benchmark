#!/bin/sh
# Gate driver for PCBV2-0020 (n8n): serializes profile startup to avoid
# SQLite migration crash in v0 (2.17.3) on warm restart.
set -u

FLAG="${PCB_FLAG:?PCB_FLAG must be set}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

_all="--profile v0 --profile v1 --profile v2"

PCB_FLAG="$FLAG" docker compose $_all down -v --remove-orphans >/dev/null 2>&1 || true
for cn in pcb-n8n-v0 pcb-n8n-v1 pcb-n8n-v2; do
    docker rm -f "$cn" >/dev/null 2>&1 || true
done

for ver in v0 v1 v2; do
    echo "[gate_driver] starting profile $ver" >&2
    PCB_FLAG="$FLAG" docker compose --profile "$ver" up -d --wait --wait-timeout 600 >&2
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "[gate_driver] profile $ver failed (rc=$rc)" >&2
        PCB_FLAG="$FLAG" docker compose $_all down -v --remove-orphans >/dev/null 2>&1 || true
        echo "{\"error\":\"compose up failed for $ver\"}"
        exit 0
    fi
    echo "[gate_driver] profile $ver ready" >&2
done

echo "[gate_driver] all profiles ready, running oracle --gate" >&2
PCB_FLAG="$FLAG" python3 oracle.py --gate
rc=$?
PCB_FLAG="$FLAG" docker compose $_all down -v --remove-orphans >/dev/null 2>&1 || true
exit $rc
