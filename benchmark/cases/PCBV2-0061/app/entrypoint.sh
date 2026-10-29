#!/bin/sh
set -e

: "${PCB_FLAG:=PCBFLAG-unset}"
echo "[entrypoint] PCB_FLAG=${PCB_FLAG}"
echo "[entrypoint] starting keystone dev (real @keystone-6/core $(node -e "console.log(require('@keystone-6/core/package.json').version)"))"

# keystone dev auto-runs prisma migrate (db push) for sqlite and serves /api/graphql
npx keystone dev --no-ui &
KS_PID=$!

GQL="http://127.0.0.1:3000/api/graphql"

echo "[entrypoint] waiting for GraphQL endpoint..."
i=0
until curl -s -o /dev/null -w '%{http_code}' -X POST "$GQL" \
      -H 'content-type: application/json' \
      -d '{"query":"{ __typename }"}' 2>/dev/null | grep -q '200'; do
  i=$((i+1))
  if [ "$i" -gt 150 ]; then
    echo "[entrypoint] GraphQL never came up" >&2
    exit 1
  fi
  sleep 2
done
echo "[entrypoint] GraphQL is up."

# Seed exactly one Secret whose protected `code` == PCB_FLAG (idempotent-ish; ignore dup).
SEED_QUERY=$(printf 'mutation { createSecret(data: { label: "primary", code: "%s" }) { id } }' "$PCB_FLAG")
BODY=$(printf '{"query":%s}' "$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$SEED_QUERY")")
echo "[entrypoint] seeding secret..."
curl -s -X POST "$GQL" -H 'content-type: application/json' -d "$BODY" || true
echo ""
# Also seed a couple of decoy rows so findMany has ordering/pagination to work with.
for d in decoy-A decoy-B decoy-C; do
  DQ=$(printf 'mutation { createSecret(data: { label: "decoy", code: "DECOY-%s" }) { id } }' "$d")
  DB=$(printf '{"query":%s}' "$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$DQ")")
  curl -s -X POST "$GQL" -H 'content-type: application/json' -d "$DB" >/dev/null || true
done
echo "[entrypoint] seed complete."

wait "$KS_PID"
