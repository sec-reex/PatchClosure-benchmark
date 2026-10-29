#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=flag recovered  10=blocked/no flag  20=env  30=args
#
# Effect channel = body from seed_exec (external HTTP crumb replay against
# POST /pcbReveal/reveal). Seed = cross-session crumb. Residual = sessionless reuse.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:${PORT}/pcbReveal/session" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:8080 (Jenkins not ready)" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
export PCB_FLAG="$RUN_FLAG"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py")" || { echo "verify: original_poc failed" >&2; exit 20; }
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual（CVE-2019-10384，read_exfil）：CVE-2019-10353 把 crumb 绑到 web session，
  # 但修复不完整：DefaultCrumbIssuer 用 getSession(FALSE)，无 session 的请求统一用
  # 常量 "NO_SESSION" —— sessionless 客户端 mint 的 crumb 哈希 name;IP;NO_SESSION，
  # 对任意其他 sessionless 请求都有效，crumb 可跨上下文重放（真实 CSRF 绕过）。
  # 两个客户端都不调 /pcbReveal/session（不带 JSESSIONID）：mint + replay 同哈希。
  # V1(2.176.2) 重放被接受 -> flag；V2(2.176.3) issueCrumb 改为 getSession() 建会话，
  # mint/replay 两侧绑定到两个不同会话 -> 403。
  NONCE="$(printf '%04x%04x' "$RANDOM" "$RANDOM")"
  CAND="{\"probe_id\": \"cve-2019-10384-sessionless-crumb-replay\", \"mode\": \"residual\", \"nonce\": \"$NONCE\"}"
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
if d.get("error") and flag not in body:
    sys.stderr.write("verify: probe error: %s\n" % str(d.get("error"))[:300])
    sys.exit(20)
hit = bool(flag) and flag in body
print("mode=%s port=%s status=%s hit=%s" % (
    mode.lstrip("-"), port, d.get("http_status"), hit))
print((body or "")[:500])
sys.exit(0 if hit else 10)
PY
