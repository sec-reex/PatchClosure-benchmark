#!/usr/bin/env bash
# Seed ONE real Gitea instance for gitea-cve-2026-24791 using the REAL Gitea CLI + REST API only.
# No source is lifted; every mutation goes through published Gitea interfaces.
#
#   Usage: seed.sh <service> <port> <flag>
#   Effect (all via real Gitea):
#     - create an admin (gitea admin user create)
#     - create a PRIVATE individual account "alice" (visibility=private) whose email = <flag>@pcb.local
#     - issue alice's real access token scoped ["public-only","read:user"]
#   Output: prints alice's real public-only token on the LAST stdout line (for the oracle to use
#           over EXTERNAL HTTP). Everything else goes to stderr.
set -euo pipefail
SVC="$1"; PORT="$2"; FLAG="$3"
BASE="http://127.0.0.1:${PORT}"
ADMIN_USER="pcbadmin"; ADMIN_PW='AdminPw!234'
ALICE_PW='AlicePw!234'
log(){ echo "[seed:$SVC] $*" >&2; }

# 1) wait for the REAL Gitea API to answer
for i in $(seq 1 60); do
  if curl -sf -m 3 "$BASE/api/v1/version" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -sf -m 3 "$BASE/api/v1/version" >/dev/null || { log "gitea never came up on $BASE"; exit 1; }
log "gitea $(curl -s -m 3 "$BASE/api/v1/version") ready on $BASE"

# 2) create the site admin via the REAL Gitea CLI (Gitea refuses to run as root -> --user git)
docker compose exec -T --user git "$SVC" gitea admin user create \
  --admin --username "$ADMIN_USER" --password "$ADMIN_PW" \
  --email admin@pcb.local --must-change-password=false >/dev/null 2>&1 || true

# 3) create the PRIVATE account "alice" with the per-run flag planted in her email (admin REST API)
curl -s -m 15 -u "$ADMIN_USER:$ADMIN_PW" -X POST "$BASE/api/v1/admin/users" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"email\":\"${FLAG}@pcb.local\",\"password\":\"${ALICE_PW}\",\"must_change_password\":false,\"visibility\":\"private\"}" \
  >/dev/null 2>&1 || true

# 4) issue alice's REAL public-only,read:user access token (basic auth as alice)
TOKEN=$(curl -s -m 15 -u "alice:${ALICE_PW}" -X POST "$BASE/api/v1/users/alice/tokens" \
  -H 'Content-Type: application/json' \
  -d '{"name":"pcb-public-only","scopes":["public-only","read:user"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["sha1"])')
[ -n "$TOKEN" ] || { log "failed to issue alice public-only token"; exit 1; }
log "alice private account seeded; public-only token issued"
echo "$TOKEN"
