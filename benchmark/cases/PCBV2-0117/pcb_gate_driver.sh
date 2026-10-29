#!/usr/bin/env bash
# GATE_DRIVER for PCBV2-0117 (gitea-cve-2026-24791)
# Containers are already deployed by gate.sh external strategy.
# We need to seed each Gitea instance (create alice + public-only token),
# then run the oracle with the tokens.
set -eu
cd "$(dirname "$0")"

FLAG="${PCB_FLAG:?PCB_FLAG must be set}"

echo "== seeding 3 real Gitea instances =="
T0=$(./seed.sh v0 39370 "$FLAG" 2>&1 | tee /dev/stderr | tail -1)
T1=$(./seed.sh v1 39371 "$FLAG" 2>&1 | tee /dev/stderr | tail -1)
T2=$(./seed.sh v2 39372 "$FLAG" 2>&1 | tee /dev/stderr | tail -1)
echo "== tokens: v0=$T0 v1=$T1 v2=$T2 =="

echo "== running oracle gate =="
PCB_TOKEN_V0="$T0" PCB_TOKEN_V1="$T1" PCB_TOKEN_V2="$T2" \
  python3 oracle.py --gate
