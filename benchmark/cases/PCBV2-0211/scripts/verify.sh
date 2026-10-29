#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0211 (urllib3-redirect-header-strip,
# CVE-2023-43804 -> CVE-2024-37891 incomplete fix).
#
# Mechanism: client container (urllib3 pinned by profile) follows a cross-ORIGIN
# 302 while carrying a sensitive header; the attacker collector echoes headers.
#   - seed     : probe.py seed      -> Cookie: session=<PCB_FLAG>
#                http://redirector/redir -> http://attacker/collect
#                V0 1.26.16 leaks; V1 1.26.17 strips Cookie (CVE-2023-43804).
#   - residual : probe.py residual  -> Proxy-Authorization: Basic <PCB_FLAG>
#                same cross-origin 302. V1 1.26.17 still leaks (strip set lacks
#                Proxy-Authorization); V2 1.26.19 strips (CVE-2024-37891).
# Flag channel: PCB_FLAG is injected into the client env by compose; the probe
# embeds it in the header; the collector echoes it. Judge uses
# JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}".
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

# residual candidate is an inline literal (heldout semantics, no hidden-file ref)
if [[ "$MODE" == "--residual" ]]; then
  printf '%s' '{"probe":"residual","header":"Proxy-Authorization"}' > "$WORK_DIR/cand.json"
else
  printf '%s' '{"probe":"seed","header":"Cookie"}' > "$WORK_DIR/cand.json"
fi

# sidecars must be up; client is ephemeral (compose run below)
RUNNING=""
N=""
for _ in $(seq 1 30); do
  N="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
       ps -q redirector attacker 2>/dev/null | wc -l | tr -d '[:space:]')"
  if [[ "$N" == "2" ]]; then RUNNING=1; break; fi
  sleep 2
done
if [[ -z "$RUNNING" ]]; then echo "verify: sidecars not running (N=$N)" >&2; exit 20; fi

export PCB_FLAG="$RUN_FLAG"
OUT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
       --profile "$VERSION" run --rm --no-deps "$SVC" python probe.py "$PROBE" 2>&1)"
RC=$?
echo "$OUT" | tail -30
if [[ "$RC" != "0" ]]; then echo "verify: docker compose run failed (rc=$RC)" >&2; exit 20; fi

if grep -q "${LABEL}_ERROR:" <<<"$OUT"; then
  echo "verify: probe reported client error" >&2
  exit 20
fi

LINE="$(grep "${LABEL}_FINAL_HEADERS:" <<<"$OUT" | head -1)"
if [[ -z "$LINE" ]]; then echo "verify: no ${LABEL}_FINAL_HEADERS line" >&2; exit 20; fi
echo "$LINE"
if [[ "$LINE" == *"$JUDGE_FLAG"* ]]; then exit 0; else exit 10; fi
