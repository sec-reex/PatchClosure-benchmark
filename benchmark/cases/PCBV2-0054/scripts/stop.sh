#!/usr/bin/env bash
# stop.sh — 停止并删除本 run 的容器/网络/卷/临时源码（仅 COMPOSE_PROJECT_NAME 范围）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile v0 --profile v1 --profile v2 --profile client \
  down --volumes --remove-orphans >/dev/null 2>&1 || true
# leftover docker-run attackers (name pcb_<run>-atk-*)
atk="$(docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}-atk-" 2>/dev/null || true)"
if [[ -n "${atk}" ]]; then
  # shellcheck disable=SC2086
  docker rm -f ${atk} >/dev/null 2>&1 || true
fi
rm -rf "$WORK_DIR"
