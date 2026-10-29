#!/usr/bin/env bash
# verify.sh --seed|--residual — dbi-cve-2026-14739（preparse 占位符展开堆溢出）
#
# 机制：容器内 REAL DBI（perl:5.40-bookworm + cpanm DBI@version）执行
#   perl /app/probe.pl <N>  ->  $dbh->preparse("?" x N, 0x200, 0x100|0x200)
# preparse() 把每个 '?' 展开为 ':p<idx>' 写入 strlen(statement)*F+16 的堆缓冲：
#   seed     N=5000      : V0(1.647, F=3) 溢出 -> SIGABRT/SIGSEGV（exit>=128）；
#                          V1(1.648, F=6) 覆盖 -> clean exit 0（len=28893）。
#   residual N=1200000   : V1 的 F=6 仍溢出（~10.4MB 展开 vs ~7.2MB 缓冲）-> crash
#                          （CVE-2026-14739）；V2(1.650, F=7 + 99999 硬上限) 干净报
#                          DBI 错误 exit 0。
# 效果通道 = probe perl 被信号杀死（exit>=128，SIGABRT 134 / SIGSEGV 139；
# perl die 的 255 除外）且 docker exec cat /pcb_flag.txt 等于当前 RUN_FLAG。
# 启动时写入的 token ≠ wrong/stale override → 10。
# 退出码：0=效果发生(crash+flag) 10=未发生(clean/mismatch) 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

# compose ps 必须带 --profile，否则 profile 服务不可见；不依赖固定 container_name
CID=""
for _ in $(seq 1 30); do
  CID="$(dc ps -q "$VERSION" 2>/dev/null | head -1 | tr -d '[:space:]')"
  if [[ -n "$CID" ]] && docker exec "$CID" test -s /pcb_flag.txt >/dev/null 2>&1; then
    break
  fi
  sleep 2
  CID=""
done
[[ -n "$CID" ]] || { echo "verify: 容器 $VERSION 未运行（compose ps 为空）" >&2; exit 20; }

N=5000
[[ "$MODE" == "--residual" ]] && N=1200000

# 长任务：docker exec 经 PCB_PYTHON 包装并限时 300s（subprocess timeout 跨平台，
# 不依赖 GNU timeout）；residual 在 V1 上 crash 前要展开 ~1.2M 占位符。
"$PY" - "$CID" "$N" <<'PYEOF'
import subprocess
import sys

cid, n = sys.argv[1], sys.argv[2]
try:
    r = subprocess.run(
        ["docker", "exec", cid, "perl", "/app/probe.pl", n],
        capture_output=True, text=True, timeout=300,
    )
    out = (r.stdout + "\n" + r.stderr).strip()
    print("verify: N=%s exit=%s out=%s" % (n, r.returncode, out[:200].replace("\n", " ")))
    sys.exit(r.returncode)
except subprocess.TimeoutExpired:
    print("verify: probe timed out after 300s", file=sys.stderr)
    sys.exit(124)
except Exception as e:
    print("verify: docker exec failed: %r" % (e,), file=sys.stderr)
    sys.exit(125)
PYEOF
RC=$?

# crash = killed by signal. docker exec maps SIGABRT/SIGSEGV to 134/139.
# Negative Python returncodes also mean a signal. perl die is 255 — not a crash.
is_crash=0
if [[ $RC -ge 128 && $RC -ne 255 ]]; then
  is_crash=1
elif [[ $RC -lt 0 ]]; then
  is_crash=1
fi

if [[ "$is_crash" == "1" ]]; then
  PLANTED="$(docker exec "$CID" cat /pcb_flag.txt 2>/dev/null | tr -d '\r\n')"
  if [[ -n "$PLANTED" && "$PLANTED" == "$RUN_FLAG" ]]; then
    echo "verify[$MODE] version=$VERSION rc=0 (crash exit=$RC + flag)" >&2
    exit 0
  fi
  echo "verify[$MODE] version=$VERSION rc=10 (crash exit=$RC, flag mismatch)" >&2
  exit 10
fi
if [[ $RC -eq 0 || $RC -eq 255 ]]; then
  echo "verify[$MODE] version=$VERSION rc=10 (clean/die exit=$RC)" >&2
  exit 10
fi
if [[ $RC -eq 124 || $RC -eq 125 ]]; then
  echo "verify[$MODE] version=$VERSION rc=20 (probe timeout/exec failed exit=$RC)" >&2
  exit 20
fi
echo "verify[$MODE] version=$VERSION rc=10 (no crash exit=$RC)" >&2
exit 10
