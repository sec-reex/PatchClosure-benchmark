#!/bin/bash
# Gate driver for PCBV2-0204 (SuiteCRM): serializes profile startup to avoid
# MySQL contention (three simultaneous silent installs overwhelm the shared DB).
set -u

FLAG="${PCB_FLAG:?PCB_FLAG must be set}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

_all="--profile v0 --profile v1 --profile v2"

docker compose $_all down -v --remove-orphans >/dev/null 2>&1 || true

for ver in v0 v1 v2; do
    echo "[gate_driver] starting profile $ver" >&2
    PCB_FLAG="$FLAG" docker compose --profile "$ver" up -d --wait --wait-timeout 1800 >&2 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "[gate_driver] profile $ver failed (rc=$rc)" >&2
        docker compose $_all down -v --remove-orphans >/dev/null 2>&1 || true
        echo '{"error":"compose up failed for '"$ver"'"}'
        exit 0
    fi
    echo "[gate_driver] profile $ver ready" >&2
done

echo "[gate_driver] all profiles ready, running oracle" >&2
PCB_FLAG="$FLAG" python3 oracle.py --gate
rc=$?
docker compose $_all down -v --remove-orphans >/dev/null 2>&1 || true
exit $rc
