#!/usr/bin/env python3
"""audit_certification.py — 合并全部认证证据，按 run_mvp.py 全门语义重算真实 certified 集合。

全门（certified）定义（与 run_mvp.py / verify_certification.py 一致）：
  v0: seed=effect_observed, wrong=effect_not_observed, stale∈(None,effect_not_observed)
  v1: seed=effect_not_observed, residual=effect_observed
  v0/v1: stop_state=stopped, residue_after_stop=0
  v0/v1: 无 error

证据来源（全部合并，按 case_id+trial_no 去重，保留所有记录用于稳定性分析）：
  reports/batch*.jsonl
  reports/runtime_trials.jsonl
  reports/mvp_certification.json   （仅含带 v0/v1 门结构的记录）

输出：
  reports/CERTIFICATION_AUDIT.md   —— 诚实状态报告（含 0015 等证据缺口）
"""
import json
import glob
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def trial_ok(tr: dict) -> bool:
    g0, g1 = tr.get("v0", {}), tr.get("v1", {})
    if g0.get("error") or g1.get("error"):
        return False
    return (
        g0.get("seed_outcome") == "effect_observed"
        and g0.get("wrong_outcome") == "effect_not_observed"
        and (g0.get("stale_outcome") in (None, "effect_not_observed"))
        and g1.get("seed_outcome") == "effect_not_observed"
        and g1.get("residual_outcome") == "effect_observed"
        and g0.get("stop_state") == "stopped" and g1.get("stop_state") == "stopped"
        and g0.get("residue_after_stop", 1) == 0 and g1.get("residue_after_stop", 1) == 0
    )


def trial_ok_score_ready(tr: dict) -> bool:
    """certified_candidate_scoring_ready 口径：start ok + correct_flag accepted + wrong rejected。"""
    s = tr.get("steps") or {}
    st = s.get("start") or {}
    cf = (s.get("correct_flag") or {}).get("resp") or {}
    wf = (s.get("wrong_flag_rejected") or {}).get("resp") or {}
    return bool(st.get("ok") and cf.get("accepted") is True and wf.get("accepted") is False)


def main():
    records = []          # (case_id, trial_no, status, ok_fullgate, ok_score, source, raw)
    src_by_case = defaultdict(set)
    files = sorted(glob.glob(str(REPORTS / "batch*.jsonl")) +
                   glob.glob(str(REPORTS / "rerun*.jsonl")) +
                   glob.glob(str(REPORTS / "tmplrerun*.jsonl")) +
                   glob.glob(str(REPORTS / "fixverify*.jsonl")) +
                   glob.glob(str(REPORTS / "fix[0-9]*.jsonl")) +
                   glob.glob(str(REPORTS / "cert*.jsonl"))) + \
        [str(REPORTS / "runtime_trials.jsonl"), str(REPORTS / "mvp_certification.json")]
    def ingest(r, fname):
        cid = r.get("case_id")
        if not cid:
            return
        # 只收两种结构：run_mvp trial 记录（含 v0/v1）或 certify 步骤记录（含 steps）
        if "v0" in r and isinstance(r.get("v0"), dict):
            records.append((cid, r.get("trial_no"), r.get("status"),
                            trial_ok(r), False, fname, r))
            src_by_case[cid].add(fname)
        elif (r.get("steps") or {}).get("start"):
            records.append((cid, r.get("trial_no"), r.get("status"),
                            False, trial_ok_score_ready(r), fname, r))
            src_by_case[cid].add(fname)

    for f in files:
        fname = Path(f).name
        try:
            raw = open(f, encoding="utf-8").read().lstrip()
            if raw.startswith("["):          # JSON 数组文件
                for r in json.loads(raw):
                    ingest(r, fname)
            else:                             # JSONL
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    ingest(json.loads(line), fname)
        except Exception as e:
            print(f"warn: {fname}: {e}", file=sys.stderr)

    by_case = defaultdict(list)
    for rec in records:
        by_case[rec[0]].append(rec)

    # 汇总
    certified_cases = []
    rows = []
    for cid in sorted(by_case):
        recs = by_case[cid]
        n_full = sum(1 for r in recs if r[3])
        n_total = len(recs)
        n_score = sum(1 for r in recs if r[4])
        n_fail = n_total - n_full
        if n_full >= 2:
            certified_cases.append(cid)
        rows.append((cid, n_full, n_total, n_score, sorted(src_by_case[cid])))

    lines = []
    lines.append("# Certification Audit（证据合并重算）\n")
    lines.append("_生成：tools/audit_certification.py，全门语义与 run_mvp.py 一致_\n")
    lines.append(f"- 证据文件数：{len(files)}")
    lines.append(f"- 有 trial 记录的 case 数：{len(by_case)}")
    lines.append(f"- **全门 certified（≥2 trials 通过）：{len(certified_cases)} 个**")
    lines.append("")
    lines.append("## 全门 certified case 清单\n")
    lines.append("| case | certified/total trials | scoring_ready | 证据文件 |")
    lines.append("|---|---|---|---|")
    for cid, n_full, n_total, n_score, srcs in rows:
        if n_full >= 2:
            lines.append(f"| {cid} | {n_full}/{n_total} | {n_score} | {', '.join(srcs)} |")
    lines.append("")
    lines.append("## 全部 case 状态（含未达 2 trials 的）\n")
    lines.append("| case | certified/total | scoring_ready | 证据文件 |")
    lines.append("|---|---|---|---|")
    for cid, n_full, n_total, n_score, srcs in rows:
        if n_full < 2:
            lines.append(f"| {cid} | {n_full}/{n_total} | {n_score} | {', '.join(srcs)} |")
    lines.append("")
    lines.append("## 7 个 MVP family 代表 case 专项核验\n")
    mvp = ["PCBV2-0002", "PCBV2-0015", "PCBV2-0018", "PCBV2-0054",
           "PCBV2-0084", "PCBV2-0086", "PCBV2-0142"]
    for cid in mvp:
        recs = by_case.get(cid, [])
        n_full = sum(1 for r in recs if r[3])
        n_total = len(recs)
        flag = "✅" if n_full >= 2 else "⚠️ 证据不足"
        lines.append(f"- {cid}: 全门 {n_full}/{n_total} {flag}")
        if n_full < 2:
            for r in recs:
                if not r[3]:
                    g0, g1 = r[6].get("v0", {}), r[6].get("v1", {})
                    lines.append(f"  - {r[5]} t{r[1]}: v0 seed={g0.get('seed_outcome')} wrong={g0.get('wrong_outcome')} | "
                                 f"v1 seed={g1.get('seed_outcome')} residual={g1.get('residual_outcome')} | "
                                 f"err={g0.get('error') or g1.get('error')}")

    out = REPORTS / "CERTIFICATION_AUDIT.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"写出 {out}")
    print(f"全门 certified: {len(certified_cases)}")
    print(" ".join(certified_cases))
    return certified_cases


if __name__ == "__main__":
    main()
