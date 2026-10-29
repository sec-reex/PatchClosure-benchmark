#!/usr/bin/env bash
# PCBV2-0067 deser_jenkins_remoting — 手写定制 verify.sh
# CVE-2015-8103 (v0 remoting 2.52: ObjectInputStreamEx 无 ClassFilter, 任意类直接反序列化)
#   -> v1 2.53 = TARGET (CVE-2015-8103 修复: ClassFilter.DEFAULT 黑名单, PcbSeed 类族被拒)
#   -> CVE-2017-1000353 (SignedObject 嵌套 ObjectInputStream 绕过外层黑名单) -> v2 3.16 SignedObject 入黑名单.
# 真实 sink: 外部 TCP 客户端 -> 真实 remoting 服务 ObjectInputStreamEx(in, cl) (Command#readFrom 形态).
# flag 通道 = canary: 服务端启动时 ${PCB_FLAG} 写入 /canary/flag.txt, PcbSeed.readObject() 读取并
#   TCP 回显 (PCB_SEED_FLAG=...). 判定用 RUN_FLAG(提交值).
# seed     = mode=direct  PcbSeed 直发 -> v0 重建读 flag(rc0); v1 外层 resolveClass 黑名单拒绝 -> 未发生(rc10)
# residual = mode=signed  PcbSeed 包进 java.security.SignedObject -> 外层只见 SignedObject(2.53 未黑),
#            getObject() 用无过滤 ObjectInputStream 重建 -> v1 读 flag(rc0); v2 SignedObject 被拒 -> 未发生
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
JUDGE_FLAG="$RUN_FLAG"

export COMPOSE_FILE="$CASE_DIR/docker-compose.yml"
export COMPOSE_PROJECT_NAME
export PCB_X="$RUN_FLAG"
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

# --- 就绪: 对 ${VERSION} 服务 9009 做 TCP 探测 (compose port 必须带 --profile) ---
APP_PORT="$(dc port "$VERSION" 9009 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$APP_PORT" ]]; then echo "verify: 无法解析 ${VERSION}:9009 端口" >&2; exit 20; fi
ready=0
for _ in $(seq 1 60); do
  if python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), 2); s.close()" "$APP_PORT" 2>/dev/null; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION}:9009 就绪超时" >&2; exit 20; fi

# --- candidate: seed=direct / residual=signed (never seed fallback) ---
if [[ "$MODE" == "--seed" ]]; then
  printf '%s' '{"id":"cve-2015-8103-direct-cli-deser-seed","mode":"direct"}' > "$WORK_DIR/cand.json"
else
  printf '%s' '{"id":"cve-2017-1000353-signedobject-nested-unfiltered-stream","mode":"signed"}' > "$WORK_DIR/cand.json"
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "verify: seed_exec 执行失败" >&2; printf '%s\n' "$OUT" >&2; exit 20; }
echo "verify: ${VERSION} ${MODE} out=$(printf '%s' "$OUT" | head -c 500)"

# --- 判定: canary 通道, 当前 RUN_FLAG 出现在客户端 TCP 回显 (PCB_SEED_FLAG=...) ---
if grep -qF "$JUDGE_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
