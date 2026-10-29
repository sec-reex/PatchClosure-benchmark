#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0070 (follow-redirects-header-strip,
# CVE-2022-0536 -> CVE-2024-28849 incomplete fix).
#
# Mechanism: client container (follow-redirects pinned by profile) fetches a redirect
# chain while carrying a sensitive header; the collector echoes the headers it received.
#   - seed     : probe.mjs seed      -> Authorization: Basic <PCB_FLAG> over
#                https://victim/redir -> http://victim/collect (same host, scheme DOWNGRADE).
#                V0 1.14.7 leaks (flag echoed); V1 1.14.8 strips (CVE-2022-0536 fix).
#   - residual : probe.mjs residual  -> Proxy-Authorization: Basic <PCB_FLAG> over
#                http://redirector/redir -> http://attacker/collect (cross-DOMAIN).
#                V1 1.14.8 still leaks (strip regex lacks proxy-authorization); V2 1.15.6 strips.
# Flag channel: PCB_FLAG is injected into the client container env by compose (server-side
# seeding = canary class); the probe embeds it in the header, the collector echoes it.
# Judge uses JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}".
# Exit: 0=effect (flag echoed) 10=no effect 20=env failure 30=arg error
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROBE="${MODE#--}"   # seed | residual
LABEL="$(printf '%s' "$PROBE" | tr '[:lower:]' '[:upper:]')"  # SEED | RESIDUAL
SVC="client-$VERSION"
mkdir -p "$WORK_DIR"

# readiness: the three persistent sidecars (victim / redirector / attacker) running;
# the client container is ephemeral (started fresh by `docker compose run` below).
RUNNING=""
for _ in $(seq 1 30); do
  N="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
       ps -q victim redirector attacker 2>/dev/null | wc -l | tr -d '[:space:]')"
  if [[ "$N" == "3" ]]; then RUNNING=1; break; fi
  sleep 2
done
if [[ -z "$RUNNING" ]]; then echo "verify: sidecars not running (N=$N)" >&2; exit 20; fi

# run the client probe inside the pinned-version container (same project/network as up -d)
export PCB_FLAG="$RUN_FLAG"
OUT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
       --profile "$VERSION" run --rm --no-deps "$SVC" node probe.mjs "$PROBE" 2>&1)"
RC=$?
echo "$OUT" | tail -30
if [[ "$RC" != "0" ]]; then echo "verify: docker compose run failed (rc=$RC)" >&2; exit 20; fi

# client-side request error => environment failure (services not reachable inside net)
if grep -q "${LABEL}_ERROR:" <<<"$OUT"; then
  echo "verify: probe reported client error" >&2
  exit 20
fi

# effect = collector echoed the flag in the received headers
LINE="$(grep "${LABEL}_FINAL_HEADERS:" <<<"$OUT" | head -1)"
if [[ -z "$LINE" ]]; then echo "verify: no ${LABEL}_FINAL_HEADERS line" >&2; exit 20; fi
echo "$LINE"
if [[ "$LINE" == *"$JUDGE_FLAG"* ]]; then exit 0; else exit 10; fi
