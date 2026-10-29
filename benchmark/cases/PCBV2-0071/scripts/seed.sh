#!/usr/bin/env bash
# seed.sh — Pre-download embedding model in already-running Open WebUI container.
# No flag row is planted; PCB_FLAG is used by verify.sh at probe time.
# The embedding warmup is the only post-start prerequisite for the verify probe.
# Assumes containers are already up and healthy. Idempotent.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi

# Pre-download the local embedding model so verify file/add is not racing HF.
timeout 180 docker compose -p "$COMPOSE_PROJECT_NAME" exec -T openwebui \
  python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')" \
  >/dev/null 2>&1 || echo "seed: embedding warmup skipped (verify will load it)" >&2
echo "seed: Open WebUI embedding model seeded"
