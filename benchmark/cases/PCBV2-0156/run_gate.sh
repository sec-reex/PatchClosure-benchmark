#!/usr/bin/env bash
# One-command reproduction for oauth2-proxy-cve-2026-40575 against REAL published oauth2-proxy.
#   - boots quay.io/oauth2-proxy/oauth2-proxy v7.10.0 (v0), v7.11.0 (v1 = target), v7.15.2 (v2)
#     in --reverse-proxy mode with a real --skip-auth-route in front of the `upstream` sidecar
#     (which serves ${PCB_FLAG} only at the PROTECTED path /foo/critical_endpoint)
#   - runs the differential flag gate over EXTERNAL HTTP (oracle.py --gate)
# No source lift, no Go harness; the bypass is an external HTTP request to the real oauth2-proxy.
set -euo pipefail
cd "$(dirname "$0")"

FLAG="${PCB_FLAG:-PCBFLAG_$(python3 -c 'import secrets;print(secrets.token_hex(16))')}"
export PCB_FLAG="$FLAG"
echo "== FLAG=$FLAG =="

echo "== booting 3 real oauth2-proxy versions + upstream sidecar =="
docker compose --profile v0 --profile v1 --profile v2 up -d

echo "== waiting for readiness + running differential flag gate (external HTTP) =="
PCB_FLAG="$FLAG" python3 oracle.py --wait
