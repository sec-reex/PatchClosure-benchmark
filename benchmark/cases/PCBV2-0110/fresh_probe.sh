#!/bin/bash
# fresh_probe.sh '<xml>'
cd "$(dirname "$0")"
docker compose --profile v1 kill v1 >/dev/null 2>&1
docker compose --profile v1 up -d >/dev/null 2>&1
for i in $(seq 1 60); do ok=$(curl -s -m 2 http://127.0.0.1:34921/health 2>/dev/null | grep -c '"ok"'); [ "$ok" -ge 1 ] && break; sleep 1; done
python3 probe_residual.py "$1"
