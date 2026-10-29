#!/usr/bin/env bash
# seed.sh — Seed pcbadmin user into already-running Gitea container.
# Assumes containers are already up and healthy. Idempotent.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi

blob=""
for _ in $(seq 1 15); do
  blob="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T -u git "$VERSION" \
    gitea admin user create --username pcbadmin --password 'Admin12345!' \
    --email admin@pcb.local --admin --must-change-password=false \
    --config /data/gitea/conf/app.ini 2>&1)" || true
  if grep -qiE 'successfully created|already exists|user already exist' <<<"$blob"; then
    echo "seed: pcbadmin seeded (${VERSION})"
    exit 0
  fi
  sleep 2
done
echo "seed: gitea admin user create failed: ${blob:0:400}" >&2
exit 1
