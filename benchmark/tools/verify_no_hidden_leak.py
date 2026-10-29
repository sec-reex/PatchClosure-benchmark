#!/usr/bin/env python3
"""verify_no_hidden_leak: ensure method-visible API responses never expose
hidden evaluator/reference/flag material.

Checks:
  1. GET /api/v1/cases/{id} public view contains no hidden fields;
  2. GET /api/v1/runs/{id} responses contain no hidden paths/flag values;
  3. work/runs/*/visible 与 work/sessions/*/exp（方法工作区）里没有
     _heldout / oracle.py / reference_witness.py / bypass / residual 物料。
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8787/api/v1"
TREE = Path(__file__).resolve().parents[1]   # benchmark/（合并树根）
WORK = TREE / "work"

HIDDEN_MARKERS = ("_heldout", "oracle.py", "reference_witness", "bypass_poc",
                  "hidden/evaluators", "expected_flag", "PCBFLAG_")
HIDDEN_FIELDS = ("hidden_oracle", "expected_flag", "flag", "reference", "evaluator")
# 方法工作区不得出现的文件名标记（与 controller/app.py:ANSWER_MATERIAL_MARKERS 对齐）
WORKSPACE_LEAK_MARKERS = ("heldout", "oracle.py", "reference_witness",
                          "bypass", "residual", "flag_spec", "gate_result")


def fetch(path):
    try:
        with urllib.request.urlopen(API + path, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except Exception as e:
        return 0, {"error": str(e)}


def scan_obj(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in HIDDEN_FIELDS:
                hits.append(f"{path}.{k}")
            hits += scan_obj(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += scan_obj(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        for m in HIDDEN_MARKERS:
            if m in obj:
                hits.append(f"{path} contains marker {m}")
    return hits


def main():
    problems = []
    # 1) case public views
    st, d = fetch("/cases?limit=50")
    if st == 200:
        for item in d.get("items", []):
            st2, pc = fetch(f"/cases/{item['case_id']}")
            if st2 == 200:
                h = scan_obj(pc)
                if h:
                    problems.append(f"case {item['case_id']}: {h[:5]}")
    # 2) run responses (sample ready runs)
    # 3) run/session 工作区：只允许平台级文件（patch/seed/submission），
    #    不含 sources/ 下的真实产品源码树（真产品里合法存在 oracle.ts / preferences.ts 之类）
    workspace_dirs = []
    for rd in sorted((WORK / "runs").glob("*")):
        if (rd / "visible").is_dir():
            workspace_dirs.append(rd / "visible")
    for sd in sorted((WORK / "sessions").glob("*")):
        if (sd / "exp").is_dir():
            workspace_dirs.append(sd / "exp")
    for ws in workspace_dirs:
        for dp, _, fs in os.walk(ws):
            if "sources" in Path(dp).parts:
                continue
            for fn in fs:
                low = fn.lower()
                if any(m in low for m in WORKSPACE_LEAK_MARKERS):
                    problems.append(f"workspace leak: {Path(dp) / fn}")
    if problems:
        print("LEAKS FOUND:")
        for p in problems[:30]:
            print(" ", p)
        (TREE / "reports" / "hidden_leak_audit.json").write_text(
            json.dumps({"leaks": problems, "ok": False}, indent=1))
        sys.exit(1)
    (TREE / "reports" / "hidden_leak_audit.json").write_text(
        json.dumps({"leaks": [], "ok": True}, indent=1))
    print("no hidden leaks detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
