#!/usr/bin/env bash
# One-command reproduction for gitea-cve-2026-24791 against REAL published Gitea.
#   - boots gitea/gitea:1.22.2 (v0), :1.26.1 (v1 = target), :1.26.2 (v2)
#   - seeds each over the REAL Gitea CLI + REST API (private account alice + public-only token)
#   - runs the differential flag gate over EXTERNAL HTTP (oracle.py --gate)
# No source lift; the bypass is an external HTTP API request with alice's real public-only token.
set -euo pipefail
cd "$(dirname "$0")"

FLAG="${PCB_FLAG:-PCBFLAG_$(python3 -c 'import secrets;print(secrets.token_hex(16))')}"
export PCB_FLAG="$FLAG"
echo "== FLAG=$FLAG =="

echo "== booting 3 real Gitea versions =="
docker compose --profile v0 --profile v1 --profile v2 up -d

echo "== seeding each real Gitea over CLI + REST =="
T0=$(./seed.sh v0 39370 "$FLAG")
T1=$(./seed.sh v1 39371 "$FLAG")
T2=$(./seed.sh v2 39372 "$FLAG")
echo "== tokens issued: v0=$T0 v1=$T1 v2=$T2 =="

echo "== differential flag gate (external HTTP) =="
PCB_FLAG="$FLAG" PCB_TOKEN_V0="$T0" PCB_TOKEN_V1="$T1" PCB_TOKEN_V2="$T2" \
  python3 oracle.py --gate
