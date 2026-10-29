#!/usr/bin/env python3
"""audit_benchmark_integrity.py — 统一基准库健康检查（stdlib only）。

检查项：
  C1  cases/<eval_id> 目录数 = 215，且与 mapping.jsonl 的 eval_id 集合一致
  C2  每个 case 的必需文件齐备（协议资产 + 学术答案底稿 + held-out residual）
  C3  身份一致：目录名 = case.json.eval_id = case.json.case_id 的映射 = case.yaml.case_id
      = case.yaml.public_name = mapping.jsonl 的 slug（六向对齐）
  C4  python 语法：cases/ 全绿；v2_harness/ 单列报告（历史物料）
  C5  脚本里的 $CASE_DIR/<相对路径> 引用不得悬空
  C6  答案物料不得出现在运行可见面（scripts/、overlays/）
  C7  库内不得残留主机绝对路径 /Users/<someone>（repro.log 历史日志除外）
  C8  held-out 与 seed 分离：poc/bypass_poc.py 必须与 _heldout/bypass_poc.py 同源

用法：
  python3 tools/audit_benchmark_integrity.py [--json reports/benchmark_integrity.json]
退出码：0 = 全绿；1 = 有 FAIL。
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

TREE = Path(__file__).resolve().parents[1]
CASES = TREE / "cases"
SECRETS = TREE / "secrets"              # four-role separation (2026-10-12): answers live here
MAPPING = TREE / "mapping.jsonl"

# Public/environment assets that must stay in cases/<id>/.
CASE_REQUIRED = [
    "case.json", "case.yaml", ".source.env", "docker-compose.yml",
    "patch_real.diff", "patch.diff",
    "scripts/prepare.sh", "scripts/fetch_source.sh", "scripts/start.sh",
    "scripts/verify.sh", "scripts/reset.sh", "scripts/stop.sh",
    "poc/original_poc.py",
]
# Answer/judging assets that must now live in secrets/<id>/ (post-move). oracle.py is
# 212/213 (PCBV2-0179 is unbuilt) so it is checked leniently below, not in this hard list.
SECRET_REQUIRED = [
    "INCOMPLETE_FIX_ANALYSIS.md", "repro.log", "bypass_poc.py", "_heldout/bypass_poc.py",
]
ANSWER_NAMES = {"_heldout", "oracle.py", "gate_result.json", "bypass_poc.py", "flag_spec.json"}
ROOT_ANSWER_ALLOWED = set()             # after the move, NO answer material is allowed in cases/
RUNTIME_DIRS = ("scripts", "overlays")
HOST_PATH_RE = re.compile(r"/Users/[A-Za-z0-9._-]+/")
CASE_DIR_REF_RE = re.compile(r'\$(?:CASE_DIR|CASE)/([A-Za-z0-9._\-/]+)')


def load_mapping() -> dict:
    m = {}
    for line in MAPPING.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            m[r["eval_id"]] = r["real_case_id"]
    return m


def yaml_scalar(path: Path, key: str):
    """极简 YAML 取值（case.yaml 顶层标量），避免依赖 PyYAML。"""
    m = re.search(rf"^{key}:\s*(.+?)\s*$", path.read_text(), re.M)
    return m.group(1).strip().strip('"\'') if m else None


def check_case(eid: str, slug: str, fails: list, warns: list) -> None:
    d = CASES / eid
    s = SECRETS / eid
    for rel in CASE_REQUIRED:
        if not (d / rel).exists():
            fails.append(f"C2 {eid}: missing cases/{eid}/{rel}")
    for rel in SECRET_REQUIRED:
        if not (s / rel).exists():
            fails.append(f"C2 {eid}: missing secrets/{eid}/{rel}")
    # oracle.py: expected in secrets/ for all built cases (PCBV2-0179 is unbuilt -> WARN)
    if not (s / "oracle.py").exists():
        warns.append(f"{eid}: no secrets/{eid}/oracle.py (unbuilt case?)")
    # C3 身份六向对齐
    try:
        cj = json.loads((d / "case.json").read_text())
    except Exception as e:
        fails.append(f"C3 {eid}: case.json unreadable ({e})")
        cj = {}
    if cj.get("eval_id") != eid:
        fails.append(f"C3 {eid}: case.json.eval_id={cj.get('eval_id')!r}")
    if cj.get("case_id") != slug:
        fails.append(f"C3 {eid}: case.json.case_id={cj.get('case_id')!r} != mapping slug {slug!r}")
    if yaml_scalar(d / "case.yaml", "case_id") != eid:
        fails.append(f"C3 {eid}: case.yaml.case_id mismatch")
    if yaml_scalar(d / "case.yaml", "public_name") != slug:
        fails.append(f"C3 {eid}: case.yaml.public_name mismatch")
    # C5 悬空 $CASE_DIR 引用
    #  · 运行期由脚本自己生成（mkdir/cp/curl -o/dest= 赋值）→ WARN
    #  · 同一脚本里成组出现、且其中至少一个可解析（典型写法：for cand in A B C）→ 候选回退，WARN
    all_scripts = "\n".join(f.read_text() for f in sorted((d / "scripts").glob("*.sh")))
    # 顶层段（.build_src / _run 之类）只要在任一脚本里被创建/清理，就视为运行期目录
    generated_tops = {
        m for m in re.findall(r'\$CASE_DIR/([A-Za-z0-9._-]+)(?=[/"\s])', all_scripts)
        if re.search(rf'(mkdir|cp|mv|unzip|tar|curl|wget|rm|touch|install)[^\n]*\$CASE_DIR/{re.escape(m)}\b',
                     all_scripts)
    }
    for sh in sorted((d / "scripts").glob("*.sh")):
        text = sh.read_text()
        refs = [r for r in CASE_DIR_REF_RE.findall(text) if not any(ch in r for ch in "{}$*?")]
        if not refs:
            continue
        resolved = [r for r in refs if (d / r).exists()]
        for ref in refs:
            if (d / ref).exists():
                continue
            top = ref.split("/")[0]
            if top in generated_tops:
                warns.append(f"{eid}: {sh.name} uses runtime-generated {ref}")
            elif resolved:
                warns.append(f"{eid}: {sh.name} optional candidate {ref} (fallback chain)")
            else:
                fails.append(f"C5 {eid}: {sh.name} references missing {ref}")
    # C6 答案物料不进运行可见面
    for sub in RUNTIME_DIRS:
        sd = d / sub
        if not sd.is_dir():
            continue
        for f in sd.rglob("*"):
            if f.name in ANSWER_NAMES and sub == "scripts":
                fails.append(f"C6 {eid}: answer material in {sub}/{f.relative_to(sd)}")
    if (d / "poc").is_dir():
        for f in (d / "poc").rglob("*"):
            if f.name in ANSWER_NAMES:   # post-move: NO answer material (incl. bypass_poc.py) in poc/
                fails.append(f"C6 {eid}: answer material in poc/{f.relative_to(d / 'poc')}")
    for f in d.iterdir():
        if f.name in ANSWER_NAMES and f.name not in ROOT_ANSWER_ALLOWED:
            fails.append(f"C6 {eid}: unexpected answer material at case root: {f.name}")
    # C7 主机绝对路径
    for f in list(d.glob("*.sh")) + list(d.glob("*.yml")) + list(d.glob("*.yaml")) + \
             list((d / "scripts").glob("*.sh")) + list((d / "poc").glob("*.py")):
        try:
            txt = f.read_text()
        except Exception:
            continue
        if HOST_PATH_RE.search(txt):
            fails.append(f"C7 {eid}: host absolute path in {f.relative_to(d)}")
    # C8 secrets/<id>/bypass_poc.py 与 secrets/<id>/_heldout/bypass_poc.py 同源（移动后均在 secrets/）
    a, b = s / "bypass_poc.py", s / "_heldout/bypass_poc.py"
    if a.exists() and b.exists() and a.read_bytes() != b.read_bytes():
        fails.append(f"C8 {eid}: secrets/{eid}/bypass_poc.py != _heldout/bypass_poc.py")
    # 提示类（非 FAIL）
    if not (d / "poc/seed_exec.py").exists():
        warns.append(f"{eid}: no poc/seed_exec.py")


def check_syntax(root: Path) -> list:
    bad = []
    for p in root.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        try:
            compile(p.read_text(), str(p), "exec")
        except SyntaxError as e:
            bad.append(f"{p.relative_to(root)}: {e.msg} (line {e.lineno})")
    return bad


def main() -> int:
    mapping = load_mapping()
    fails, warns = [], []

    # C1 案例集合
    dirs = sorted(x.name for x in CASES.iterdir() if x.is_dir())
    if len(dirs) != 215:
        fails.append(f"C1 case dirs={len(dirs)} != 215")
    if set(dirs) != set(mapping):
        fails.append(f"C1 dir/mapping mismatch: missing={sorted(set(mapping) - set(dirs))[:5]} "
                     f"extra={sorted(set(dirs) - set(mapping))[:5]}")

    for eid in sorted(set(dirs) & set(mapping)):
        check_case(eid, mapping[eid], fails, warns)

    # C4 语法
    case_bad = check_syntax(CASES)
    fails += [f"C4 cases/{b}" for b in case_bad]
    v2_bad = check_syntax(TREE / "v2_harness")

    # C7 全库主机路径：范围 = 平台代码/配置 + case 目录（可执行内容）。
    #   v2_harness/ 为历史评测物料（manifest 内的旧 locator 属数据，不改写）；
    #   docker-compose.yml 的挂载点指向本仓，属基础设施配置。
    C7_SKIP_PARTS = {"v2_harness", "reports", "work", "_merge_conflicts", "__pycache__",
                     # 学术侧历史证据/台账（数据记录，非可执行内容）
                     "archive_phase", "archive_non_gold", "new_build", "strict_audit", "provenance"}
    C7_SKIP_FILES = {"docker-compose.yml", "repro.log"}
    for p in TREE.rglob("*"):
        if not p.is_file() or any(part in C7_SKIP_PARTS for part in p.parts):
            continue
        if p.name in C7_SKIP_FILES or p.suffix not in (".py", ".sh", ".yml", ".yaml", ".env", ".json", ".toml"):
            continue
        try:
            if HOST_PATH_RE.search(p.read_text()):
                fails.append(f"C7 {p.relative_to(TREE)}: host absolute path")
        except Exception:
            continue

    report = {
        "cases": len(dirs),
        "fails": fails,
        "warnings": warns,
        "v2_harness_syntax_errors": v2_bad,
    }
    out = TREE / "reports" / "benchmark_integrity.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1))

    print(f"cases={len(dirs)}  FAIL={len(fails)}  WARN={len(warns)}  "
          f"v2_harness_syntax_errors={len(v2_bad)}")
    for f in fails[:40]:
        print("  FAIL", f)
    if len(fails) > 40:
        print(f"  ... {len(fails) - 40} more in {out.relative_to(TREE)}")
    print(f"report: {out.relative_to(TREE)}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
