#!/usr/bin/env python3
"""migrate_case.py — [历史 · pre-merge r24 迁移] 从旧 benchmark 布局迁移 case 到平台布局。

合并后 benchmark/ 与 benchmark_platform/ 已是同一棵树（cases/<eval_id>/ 同时带学术 case.json
与平台 case.yaml），因此本脚本不再参与发布流程：其输入 OLD_CASES（旧 benchmark/cases/<slug>/）
已不存在，保留仅作 provenance。下面路径常量已指向合并后的实际位置。

输入（只读）：
  benchmark/v2_harness/inputs/<case-id>/input_manifest.json   -> source/runtime_kind
  mapping.jsonl                                               -> eval_id -> real_case_id
  reports/platform_inventory.json                             -> oracle_family 推导结果
  benchmark/cases/<real_case_id>/                             -> compose / original_poc.py / patch.diff

输出（新目录，不触碰旧 benchmark）：
  cases/<case-id>/
    case.yaml  .source.env  docker-compose.yml(迁移版)  poc/original_poc.py
    scripts/{prepare,fetch_source,start,verify,reset,stop}.sh  overlays/

用法：
  python3 tools/migrate_case.py PCBV2-0002 [--force]
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

TREE = Path(__file__).resolve().parents[1]   # benchmark/（合并树根）
ROOT = TREE.parent                            # repo root
V2_INPUTS = TREE / "v2_harness" / "inputs"
# 历史工具（pre-merge r24 迁移）：旧 benchmark/cases/<slug>/ 布局在合并后已不存在，
# 保留仅作 provenance。合并后的 case 目录 = cases/<eval_id>/（学术 case.json 与平台 case.yaml 同处）。
OLD_CASES = ROOT / "benchmark" / "cases"
CASES_OUT = TREE / "cases"

SCHEMA_VERSION = "case-protocol-v2-1"


def load_mapping():
    m = {}
    p = TREE / "mapping.jsonl"
    if p.exists():
        for l in p.read_text().splitlines():
            l = l.strip()
            if not l:
                continue
            x = json.loads(l)
            m[x["eval_id"]] = x.get("real_case_id")
    return m


def load_family():
    fam = {}
    p = ROOT / "reports" / "platform_inventory.json"
    if p.exists():
        for c in json.loads(p.read_text()):
            fam[c.get("case_id")] = c.get("oracle_family")
    return fam


def git_repo_url(repo: str) -> str:
    """规范化 repo 名为 https://github.com/<owner>/<name>.git 形态（保守）。"""
    repo = repo.strip().rstrip("/")
    if repo.startswith(("http://", "https://")):
        return repo + ".git" if not repo.endswith(".git") else repo
    if ":" in repo and "/" in repo:  # scp-like: owner/name
        return f"https://github.com/{repo}.git"
    if "/" in repo:  # owner/name（无协议）→ github 默认
        return f"https://github.com/{repo}.git"
    return repo


def migrate_compose(src: Path, dst: Path, cid: str = "") -> list:
    """复制 compose 并做协议化迁移；返回迁移说明列表。"""
    text = src.read_text(encoding="utf-8", errors="ignore")
    notes = []
    # 1) 去掉固定 container_name（多 run 隔离靠 COMPOSE_PROJECT_NAME）
    n0 = len(re.findall(r"container_name:\s*\S+", text))
    text = re.sub(r"^\s*container_name:\s*\S+\s*$", "", text, flags=re.M)
    if n0:
        notes.append(f"removed {n0} fixed container_name")
    # 1.5) 独立网络 subnet（并行时多个 compose 网络防冲突）
    if "networks:" not in text:
        text += f"""
networks:
  default:
    ipam:
      config:
        - subnet: 172.31.{int(cid.replace('PCBV2-', '')) % 250 + 1}.0/24
"""
    # 2) 端口映射：host 固定端口改为 ${PORT_<svc>_<idx>:-<原端口>} 插值（start.sh 分配）
    def _port_repl(m):
        svc, idx, host, cont = m.group(1), len(re.findall(r"PORT_", text[:m.start()])), m.group(2), m.group(3)
        return f'      - "${{PORT_{svc}_{idx}:-{host}}}:{cont}"'
    n1 = len(re.findall(r'ports:\s*\n(\s+-\s*"(\d+):(\d+)"\s*\n)+', text))
    text = re.sub(r'^\s+-\s*"(\d+):(\d+)"\s*$', lambda m: f'      - "${{PORT_{m.group(1)}_{0}:-{m.group(1)}}}:{m.group(2)}"', text, flags=re.M)
    if n1:
        notes.append(f"ported {n1} port mappings to ${{PORT_...}} interpolation")
    dst.write_text(text)
    return notes


def _compose_build_contexts(compose_path: Path) -> list:
    """提取 compose 的 build context 路径（去重）。"""
    text = compose_path.read_text(encoding="utf-8", errors="ignore")
    ctxs = []
    for m in re.finditer(r'build:\s*\{\s*context:\s*([^,}]+)', text):
        c = m.group(1).strip().strip('"').strip("'")
        if c not in ctxs:
            ctxs.append(c)
    for m in re.finditer(r'(?m)^\s*context:\s*([^#\n]+)', text):
        c = m.group(1).strip().strip('"').strip("'")
        if c not in ctxs:
            ctxs.append(c)
    # 字符串形式 build: ./servers（非字典/块形式）
    for m in re.finditer(r'(?m)^\s*build:\s*([^#{}\n]+)', text):
        c = m.group(1).strip().strip('"').strip("'")
        c = c.split()[0] if c else ""
        if c and c not in ctxs:
            ctxs.append(c)
    return ctxs


def _compose_container_ports(compose_text: str) -> list:
    """从 compose 提取容器端口（ports 声明的右侧），去重排序。"""
    ports = set()
    for m in re.finditer(r'(?m)^\s*-\s*"?[^"]*:(\d+)"?\s*$', compose_text):
        ports.add(int(m.group(1)))
    for m in re.finditer(r'ports:\s*\["?(?:\d+):(\d+)"?\]', compose_text):
        ports.add(int(m.group(1)))
    return sorted(ports)


def _compose_mount_rels(compose_path: Path) -> list:
    """提取 compose volumes 里 ./相对路径 的 host 侧路径（去重，按出现序）。"""
    text = compose_path.read_text(encoding="utf-8", errors="ignore")
    rels = []
    for m in re.finditer(r'(?m)^\s*-\s*"?\./([^":]+)"?:', text):
        rel = m.group(1).strip()
        if rel and rel not in rels and not rel.startswith((".", "/")):
            rels.append(rel)
    return rels


def gen_scripts(case_dir: Path, source_type: str, cid: str, real: str) -> None:
    scripts = case_dir / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    existing = {p.name for p in scripts.glob("*.sh")}
    src_env = f"""# generated by migrate_case.py — fetch_source.sh 读此文件（无 yaml 依赖）
REPO={git_repo_url("__REPO__")}
V0=__V0__
V1=__V1__
TYPE={source_type}
"""
    (case_dir / ".source.env").write_text(src_env)
    _WRITE_KEEP = {}
    # prepare.sh
    if "prepare.sh" not in existing:
        (scripts / "prepare.sh").write_text("""#!/usr/bin/env bash
# prepare.sh — 业务初始化（migration/建库/建用户/fixture）。必须幂等；失败非零。
# 平台注入：RUN_ID COMPOSE_PROJECT_NAME RUN_FLAG VERSION WORK_DIR
set -euo pipefail
# TODO(case): 实现本 case 的初始化（默认无操作，视为幂等成功）
exit 0
""")
    # fetch_source.sh
    (scripts / "fetch_source.sh").write_text("""#!/usr/bin/env bash
# fetch_source.sh --version v0|v1 --dest DIR — 按需拉取准确版本源码（shallow）。
set -euo pipefail
V=""; DEST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) V="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 30 ;;
  esac
done
[[ -n "$V" && -n "$DEST" ]] || { echo "usage: --version v0|v1 --dest DIR" >&2; exit 30; }
[[ "$V" == "v0" || "$V" == "v1" ]] || { echo "bad version: $V" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"
REF=""; [[ "$V" == "v0" ]] && REF="$V0" || REF="$V1"
rm -rf "$DEST"; mkdir -p "$DEST"
if [[ "$TYPE" == "git" ]]; then
  BRANCH=""
  # tag 变体匹配：$REF / v$REF / REL-${REF//./_}（如 pgAdmin 的 REL-9_15）
  for cand in "$REF" "v$REF" "REL-${REF//./_}"; do
    if git ls-remote --exit-code --tags "$REPO" "refs/tags/$cand" >/dev/null 2>&1; then
      BRANCH="$cand"
      break
    fi
  done
  if [[ -z "$BRANCH" ]]; then
    # 模糊匹配：任意前缀/分隔符 tag 以 $REF 结尾（如 n8n@2.17.3）
    FZ="$(git ls-remote --tags "$REPO" 2>/dev/null | sed 's|.*refs/tags/||' | grep -E "(^|@|-|\.)${REF//./\\.}$" | head -1)"
    if [[ -n "$FZ" ]]; then BRANCH="$FZ"; fi
  fi
  if [[ -n "$BRANCH" ]]; then
    git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$DEST" || { echo "clone $BRANCH failed" >&2; exit 20; }
  else
    git init -q "$DEST" && cd "$DEST" \\
      && git remote add origin "$REPO" \\
      && git fetch -q --depth 1 origin "$REF" \\
      && git checkout -q FETCH_HEAD || { echo "fetch $REF failed" >&2; exit 20; }
  fi
  echo "fetched $REPO@$REF -> $DEST"
else
  echo "source_type=$TYPE not supported by template" >&2; exit 20
fi
""")
    # start.sh
    (scripts / "start.sh").write_text("""#!/usr/bin/env bash
# start.sh — 启动 compose 并把 RUN_FLAG 注入目标。平台注入 RUN_ID/COMPOSE_PROJECT_NAME/RUN_FLAG/VERSION/WORK_DIR。
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# 为每个 PORT_<svc>_<idx> 变量分配高位随机端口（compose 插值；无则跳过）
PORTS="$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
out = []
for n in names:
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'PORT_{n}={p}')
            break
print(' '.join(out))
PY
)"
if [[ -n "$PORTS" ]]; then export "$PORTS"; fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d
""")
    # verify.sh（模板 v2：poc/seed_exec.py 执行 candidate + RUN_FLAG 判定；residual 由 case 补）
    (scripts / "verify.sh").write_text("""#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed 路径：poc/seed_exec.py <candidate.json> <version>（公开执行器）；residual 需 case 补实现。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port v1 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
export PCB_TARGET_PORT="${PORT:-}"
if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-{}}"
  # 容错：非 JSON 输出（如纯路径字符串）包装成 {"path": ...}
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # TODO(case): 实现 residual 路径（V1 上仍达效果的另一条路径）；默认等价 seed（需 case 覆盖）
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-{}}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or '')
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
""")
    # reset.sh
    (scripts / "reset.sh").write_text("""#!/usr/bin/env bash
# reset.sh — 恢复到本次 trial 初始状态（down --volumes + up，flag 重新注入）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d
""")
    # stop.sh
    (scripts / "stop.sh").write_text("""#!/usr/bin/env bash
# stop.sh — 停止并删除本 run 的容器/网络/卷/临时源码（仅 COMPOSE_PROJECT_NAME 范围）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile v0 --profile v1 --profile v2 down --volumes --remove-orphans >/dev/null 2>&1 || true
rm -rf "$WORK_DIR"
""")
    for s in ("prepare", "fetch_source", "start", "verify", "reset", "stop"):
        p = scripts / f"{s}.sh"
        p.chmod(0o755)
    (case_dir / "overlays").mkdir(exist_ok=True)


def migrate(cid: str, force: bool = False) -> dict:
    mapping = load_mapping()
    family = load_family()
    real = mapping.get(cid)
    if not real:
        return {"case_id": cid, "status": "mapping_missing"}
    im = json.loads((V2_INPUTS / cid / "input_manifest.json").read_text())
    patch = im.get("patch", {})
    prov = patch.get("provenance", {})
    repo = prov.get("repo") or patch.get("repo") or ""
    v0 = patch.get("v0_ref") or ""
    v1 = patch.get("v1_ref") or ""
    src_type = "git" if repo else "unknown"
    runtime = im.get("environment", {}).get("runtime_kind", "unknown")
    run_mode = {"http": "real-app-http", "tcp": "real-app-tcp",
                "cli": "real-app-cli"}.get(runtime, "unknown")
    fam = family.get(cid) or im.get("effect_contract", {}).get("effect_class") or "unknown"

    out = CASES_OUT / cid
    if (out / "case.yaml").exists() and not force:
        return {"case_id": cid, "status": "exists", "path": str(out)}
    if out.exists():
        shutil.rmtree(out)
    (out / "scripts").mkdir(parents=True)
    (out / "poc").mkdir(parents=True)

    # case.yaml（cports 在 compose 迁移后计算）
    cports_str = "80"
    yaml_text = f"""case_id: {cid}
public_name: {real}
run_mode: {run_mode}
oracle_family: {fam}
compose_file: docker-compose.yml
scripts:
  prepare: scripts/prepare.sh
  fetch_source: scripts/fetch_source.sh
  start: scripts/start.sh
  verify: scripts/verify.sh
  reset: scripts/reset.sh
  stop: scripts/stop.sh
source:
  type: {src_type}
  repo: {git_repo_url(repo)}
  v0: {v0}
  v1: {v1}
service:
  readiness: http://127.0.0.1:{cports_str}/
  exposed_ports: [{cports_str}]
verification:
  seed_command: [scripts/verify.sh, --seed]
  residual_command: [scripts/verify.sh, --residual]
"""
    (out / "case.yaml").write_text(yaml_text)

    # compose 迁移
    old_compose = OLD_CASES / real / "docker-compose.yml"
    notes = []
    if old_compose.exists():
        notes = migrate_compose(old_compose, out / "docker-compose.yml", cid=cid)
        # 复制 compose 挂载的相对路径（./conf/... ./data/... 等），否则容器挂载到空目录
        for rel in _compose_mount_rels(old_compose):
            s = OLD_CASES / real / rel
            d = out / rel
            if s.is_dir():
                shutil.copytree(s, d, dirs_exist_ok=True)
                notes.append(f"copied dir {rel}/")
            elif s.is_file():
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(s, d)
                notes.append(f"copied file {rel}")
    else:
        (out / "docker-compose.yml").write_text(
            "# compose 迁移失败：旧 case 无 docker-compose.yml，需手工提供\n")

    # compose 已迁移：更新 case.yaml 的 exposed_ports（容器端口）
    cports = _compose_container_ports(
        (out / "docker-compose.yml").read_text(encoding="utf-8", errors="ignore"))
    cports_str = ", ".join(str(p) for p in cports) or "80"
    (out / "case.yaml").write_text(
        (out / "case.yaml").read_text()
        .replace("readiness: http://127.0.0.1:80/", f"readiness: http://127.0.0.1:{cports_str}/")
        .replace("exposed_ports: [80]", f"exposed_ports: [{cports_str}]"))

    # build context 复制（compose 引用 . 或相对目录时，把旧 case 的非 hidden 内容复制过来，
    # 否则容器 build 会因缺 Dockerfile 等失败）
    bctx = _compose_build_contexts(old_compose) if old_compose.exists() else []
    if bctx and any(c in ("", ".") for c in bctx):
        for item in sorted(OLD_CASES.iterdir()):
            if item.name != real:
                continue
            for sub in sorted(item.iterdir()):
                if sub.name in ("_heldout", ".git", "__pycache__", "node_modules", ".venv",
                                "oracle.py", "gate_result.json"):
                    continue
                dst = out / sub.name
                if sub.is_dir():
                    shutil.copytree(sub, dst, dirs_exist_ok=True)
                    notes.append(f"copied build ctx dir {sub.name}/")
                else:
                    shutil.copy2(sub, dst)
                    notes.append(f"copied build ctx file {sub.name}")
    elif bctx:
        for c in bctx:
            if c in ("", "."):
                continue
            s = OLD_CASES / real / c
            if s.is_dir():
                shutil.copytree(s, out / c, dirs_exist_ok=True)
                notes.append(f"copied build ctx {c}/")
            elif s.is_file():
                shutil.copy2(s, out / c)
                notes.append(f"copied build ctx {c}")

    # poc（original_poc.py / seed_exec.py 存在则复制；seed_exec 是公开执行器非 hidden）
    old_poc = OLD_CASES / real / "original_poc.py"
    if old_poc.exists():
        shutil.copy2(old_poc, out / "poc" / "original_poc.py")
    else:
        (out / "poc" / "original_poc.py").write_text(
            "# 迁移：旧 case 无 original_poc.py，verify.sh 需手工适配\n")
    v2_seed_exec = V2_INPUTS / cid / "seed_exec.py"
    if v2_seed_exec.exists():
        shutil.copy2(v2_seed_exec, out / "poc" / "seed_exec.py")

    # scripts（模板含真实 source 值；--force 重新生成模板，手工精调脚本需在迁移后重写）
    gen_scripts(out, src_type, cid, real)
    for s in ("prepare", "fetch_source", "start", "verify", "reset", "stop"):
        (out / "scripts" / f"{s}.sh").chmod(0o755)
    env_p = out / ".source.env"
    env_p.write_text(env_p.read_text()
                     .replace("__REPO__", git_repo_url(repo))
                     .replace("__V0__", v0)
                     .replace("__V1__", v1))

    return {"case_id": cid, "status": "migrated", "real_case_id": real,
            "oracle_family": fam, "source_type": src_type,
            "repo": git_repo_url(repo), "v0": v0, "v1": v1,
            "compose_notes": notes, "path": str(out)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case_ids", nargs="+")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--all", action="store_true", help="迁移全部 215（按 inventory 顺序）")
    args = ap.parse_args()
    ids = args.case_ids
    if args.all:
        inv = json.loads((ROOT / "reports" / "platform_inventory.json").read_text())
        ids = [c["case_id"] for c in inv]
    out = []
    for cid in ids:
        r = migrate(cid, force=args.force)
        out.append(r)
        print(json.dumps(r, ensure_ascii=False))
    n_ok = sum(1 for r in out if r.get("status") == "migrated")
    n_exist = sum(1 for r in out if r.get("status") == "exists")
    print(f"migrated={n_ok} exists={n_exist} failed={len(out) - n_ok - n_exist}")


if __name__ == "__main__":
    main()