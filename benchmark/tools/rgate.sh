#!/usr/bin/env bash
# rgate.sh —— 源码目录在本机、实际执行环境在 gpu1_wg 的门禁运行器
#
# 用法:
#   benchmark/tools/rgate.sh PCBV2-0001              # 等价于远端 python3 oracle.py --run-gate
#   benchmark/tools/rgate.sh PCBV2-0001 --probe v1   # 额外参数原样传给 oracle.py
#   PCB_FLAG=PCBFLAG_xxx benchmark/tools/rgate.sh PCBV2-0001   # 指定 canary（不设则由 oracle 自取）
#
# 环境变量:
#   RGATE_HOST        远端主机 ssh 别名（默认 gpu1_wg，即 10.7.0.11 RelayFlex 直连）
#   RGATE_REMOTE_ROOT 远端基准镜像根（默认 /home/user/LLMs/patch_closure/benchmark_platform）
#   RGATE_TIMEOUT     远端单次执行超时秒数（默认 570）
#
# 机制:
#   1) 增量 rsync 当前案目录到远端镜像（秒级，本机永远是唯一事实源）；
#   2) 在远端镜像目录里执行 oracle.py —— compose build/up/探测/down 全部发生在 gpu1_wg 本地，
#      bind mount、端口发布、镜像 pull 均无跨机问题；
#   3) PYTHONPATH 附带 poc/ 与 _heldout/，兼容 oracle.py 从案根导入 original_poc 的形状；
#      远端 patch_closure/benchmark -> benchmark_platform 软链接兜底 flag_oracle 的路径形状。
#
# 注意:
#   单向推送——远端运行中生成的文件不会被自动拉回本机；
#   日常查看远端容器可用 docker context gpu1wg（docker --context gpu1wg ps / logs）。

set -euo pipefail

HOST="${RGATE_HOST:-gpu1_wg}"
REMOTE_ROOT="${RGATE_REMOTE_ROOT:-/home/user/LLMs/patch_closure/benchmark_platform}"
TIMEOUT="${RGATE_TIMEOUT:-570}"

CASE_ID="${1:-}"; shift || true
[ -n "$CASE_ID" ] || { sed -n '2,24p' "$0" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"           # benchmark/tools
LOCAL_CASE="$HERE/../cases/$CASE_ID"
LOCAL_SECRET="$HERE/../secrets/$CASE_ID"         # four-role split (2026-10-12): answers live here
[ -d "$LOCAL_CASE" ] || { echo "rgate: 本机没有 benchmark/cases/$CASE_ID" >&2; exit 2; }
[ -d "$LOCAL_SECRET" ] || { echo "rgate: 本机没有 benchmark/secrets/$CASE_ID（答案目录；oracle.py/_heldout 已迁入 secrets/）" >&2; exit 2; }
[ -f "$LOCAL_SECRET/oracle.py" ] || { echo "rgate: secrets/$CASE_ID 无 oracle.py（该案可能未构建，如 PCBV2-0179）" >&2; exit 3; }

# 1) 路径形状兜底（oracle.py 的 parents[2]/benchmark）+ 增量推送。
#    远端 cases/<id>/ 目录是「公开定义(cases) + 答案(secrets) 合并视图」，
#    这样 oracle.py 的 HERE 相对路径（_heldout/、poc/original_poc）保持原形状、字节不改。
ssh -o BatchMode=yes "$HOST" "cd '$REMOTE_ROOT/..' && [ -e benchmark ] || ln -s '$(basename "$REMOTE_ROOT")' benchmark"
rsync -a --delete --exclude='__pycache__/' "$LOCAL_CASE/" "$HOST:$REMOTE_ROOT/cases/$CASE_ID/"
# overlay 答案（不 --delete，叠加到合并视图；oracle.py、_heldout/、bypass_poc.py 等）
rsync -a --exclude='__pycache__/' "$LOCAL_SECRET/" "$HOST:$REMOTE_ROOT/cases/$CASE_ID/"

# 2) 远端执行
ARGS=("$@")
[ ${#ARGS[@]} -eq 0 ] && ARGS=(--run-gate)
ssh -o BatchMode=yes "$HOST" "cd '$REMOTE_ROOT/cases/$CASE_ID' && export PYTHONPATH=\"\$PWD/poc:\$PWD/_heldout\${PYTHONPATH:+:\$PYTHONPATH}\" && PCB_FLAG='${PCB_FLAG:-}' timeout '$TIMEOUT' python3 oracle.py ${ARGS[*]}"
