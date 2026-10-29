#!/usr/bin/env python3
"""audit_case_protocol.py — 静态协议审计（Round 24 v2 任务书 §7）。

对每个已迁移 case 检查：
  1. case.yaml 可解析且含必需字段（scripts/source/service/compose_file）
  2. 6 个脚本存在且可执行
  3. source v0/v1 字段完整
  4. docker-compose.yml 存在
  5. PoC / 验证入口存在（poc/ 下至少一个文件）
  6. 答案物料不进入运行/方法可见面：scripts/ 与 overlays/ 无 hidden 文件；
     poc/ 只允许规范答案名 bypass_poc.py；case 根目录只允许文档化的
     _heldout/、oracle.py、gate_result.json（合并后答案底稿与 case 同目录是库布局）
  7. case.yaml 的 scripts 路径与 scripts/ 目录一致

输出：reports/case_protocol_audit.jsonl（每 case 一行，status=protocol_ready|case_protocol_missing）
退出码：非零 = 存在 protocol_ready 之外的状态（暴露失败）。
"""
import json
import os
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "cases"
OUT = ROOT / "reports" / "case_protocol_audit.jsonl"

REQUIRED_SCRIPTS = ["prepare", "fetch_source", "start", "verify", "reset", "stop"]
HIDDEN_NAMES = {"_heldout", "oracle.py", "gate_result.json", "bypass_poc.py", "flag_spec.json"}
# 合并后：根目录允许的答案底稿（repro.log/patch 等不是 hidden 名，不在此列）
ROOT_ANSWER_ALLOWED = {"_heldout", "oracle.py", "gate_result.json"}
# poc/ 下允许的唯一答案物料（seed 物料不限）
POC_ANSWER_ALLOWED = {"bypass_poc.py"}
# 平台会执行 / 拷入运行环境的目录：绝不带答案物料
RUNTIME_DIRS = ("scripts", "overlays")


def audit_case(cid: str) -> dict:
    d = CASES / cid
    missing = []
    # 1) case.yaml
    cy = d / "case.yaml"
    if not cy.exists():
        return {"case_id": cid, "status": "case_protocol_missing", "missing": ["case.yaml"]}
    try:
        m = yaml.safe_load(cy.read_text())
    except Exception as e:
        return {"case_id": cid, "status": "case_protocol_missing", "missing": [f"case.yaml parse: {e}"]}
    for k in ("scripts", "source", "service", "compose_file", "case_id"):
        if k not in m:
            missing.append(f"case.yaml.{k}")
    # 2) 脚本存在可执行
    scripts = m.get("scripts", {})
    for s in REQUIRED_SCRIPTS:
        sp = d / scripts.get(s, "")
        if not sp.exists() or not os.access(sp, os.X_OK):
            missing.append(f"script:{s}")
    # 3) source 字段
    src = m.get("source", {})
    for k in ("type", "repo", "v0", "v1"):
        if not str(src.get(k, "")).strip():
            missing.append(f"source.{k}")
    # 4) compose
    if not (d / m.get("compose_file", "docker-compose.yml")).exists():
        missing.append("compose_file")
    # 5) PoC
    poc = d / "poc"
    if not poc.exists() or not any(poc.iterdir()):
        missing.append("poc")
    # 6) 答案物料只在文档化位置（库布局）；运行可见面绝不带答案物料
    for item in d.iterdir():
        if item.name in HIDDEN_NAMES and item.name not in ROOT_ANSWER_ALLOWED:
            missing.append(f"hidden:root/{item.name}")
    for sub_name in RUNTIME_DIRS:
        sub_dir = d / sub_name
        if not sub_dir.is_dir():
            continue
        for sub in sub_dir.rglob("*"):
            if sub.name in HIDDEN_NAMES:
                missing.append(f"hidden:{sub_name}/{sub.relative_to(sub_dir)}")
    poc = d / "poc"
    if poc.is_dir():
        for sub in poc.rglob("*"):
            if sub.name in HIDDEN_NAMES and sub.name not in POC_ANSWER_ALLOWED:
                missing.append(f"hidden:poc/{sub.relative_to(poc)}")
    status = "protocol_ready" if not missing else "case_protocol_missing"
    return {"case_id": cid, "status": status, "missing": missing}


def main():
    ids = sorted(p.name for p in CASES.iterdir() if (p / "case.yaml").exists())
    if not ids:
        print("no migrated cases", file=sys.stderr)
        sys.exit(2)
    rows = []
    for cid in ids:
        r = audit_case(cid)
        rows.append(r)
        print(json.dumps(r, ensure_ascii=False))
    with OUT.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    n_ok = sum(1 for r in rows if r["status"] == "protocol_ready")
    n_missing = sum(1 for r in rows if r["status"] == "case_protocol_missing")
    print(f"\naudit: {n_ok} protocol_ready / {n_missing} case_protocol_missing / {len(rows)} total")
    sys.exit(0 if n_missing == 0 else 1)


if __name__ == "__main__":
    main()
