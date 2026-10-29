#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2022-1292 $(...) in link_hash_cert filename (V0 fires; V1 list-form blocks)
# residual: CVE-2022-2068 trailing-pipe 2-arg open (V1 still fires)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR"

# seed_exec.py cwd=poc/ and does not pass -p/--project-directory; provide compose context.
# PCB_FLAG is interpolated into the one-shot container by docker-compose.yml.
export COMPOSE_FILE="$CASE_DIR/docker-compose.yml"
export COMPOSE_PROJECT_NAME
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" - "$CASE_DIR/poc" > "$WORK_DIR/cand.json" <<'PYEOF'
import sys, json
sys.path.insert(0, sys.argv[1])
import original_poc
print(json.dumps(original_poc.candidate()))
PYEOF
else
  # residual: CVE-2022-2068 trailing-pipe filename (check_file 2-arg open).
  # Inline literal only; entrypoint residual flavor plants a.pem;echo $PCB_FLAG>resid_out|
  printf '%s\n' '{"probe_id":"cve-2022-2068-residual","flavor":"residual"}' > "$WORK_DIR/cand.json"
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }

export JUDGE_FLAG
"$PY" - "$OUT" <<'PYEOF'
import json, os, re, sys
raw = sys.argv[1]
try:
    d = json.loads(raw)
except Exception:
    print("verify: bad executor output", raw[:300], file=sys.stderr)
    sys.exit(20)
blob = "\n".join([
    str(d.get("stdout") or ""),
    str(d.get("stderr") or ""),
    str(d.get("body") or ""),
    raw,
])
print(blob[:500])
if re.search(
    r"no such service|no configuration file|error during connect|Cannot connect|"
    r"not running|pull access denied|image .* not found|set PCB_FLAG|"
    r"Pool overlaps|failed to create network|network .* already exists",
    blob,
    re.I,
):
    print("verify: docker/compose error (env):", blob[:300], file=sys.stderr)
    sys.exit(20)
ref = os.environ.get("JUDGE_FLAG") or os.environ.get("RUN_FLAG_REF") or os.environ["RUN_FLAG"]
if ref and ref in blob:
    sys.exit(0)
sys.exit(10)
PYEOF
