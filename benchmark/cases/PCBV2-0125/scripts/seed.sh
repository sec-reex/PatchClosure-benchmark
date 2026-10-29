#!/usr/bin/env bash
# seed.sh — Plant per-run flag into Loki ruler group YAML (bind-mounted into container).
# The YAML file at _run/pcb_flag.yaml is mounted read-only at /loki/pcb_flag.yaml
# inside the Loki container. A successful path-traversal probe reads this file.
# Assumes containers are already up and healthy. Idempotent (overwrites file).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi

mkdir -p "$CASE_DIR/_run"
cat > "$CASE_DIR/_run/pcb_flag.yaml" <<PLANT
groups:
  - name: $FLAG
    rules:
      - alert: PcbCanary
        expr: 'count_over_time({job="pcb"}[5m]) > 0'
        for: 1m
        labels:
          severity: info
        annotations:
          summary: pcb canary
PLANT
echo "seed: Loki flag YAML planted (${VERSION})"
