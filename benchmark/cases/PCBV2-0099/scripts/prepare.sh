#!/usr/bin/env bash
# prepare.sh — 业务初始化（migration/建库/建用户/fixture）。必须幂等；失败非零。
# 平台注入：RUN_ID COMPOSE_PROJECT_NAME RUN_FLAG VERSION WORK_DIR
set -euo pipefail
# TODO(case): 实现本 case 的初始化（默认无操作，视为幂等成功）
exit 0
