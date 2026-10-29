#!/usr/bin/env python3
"""verify_certification.py — 校验 runtime_trials.jsonl 的认证结果（Round 24 v2）。

认证（certified）必须满足每条 trial：
  v0 run: seed=effect_observed, wrong=effect_not_observed, stale=effect_not_observed(有 stale 时),
          stop_state=stopped, residue_after_stop=0
  v1 run: seed=effect_not_observed(blocked), residual=effect_observed,
          stop_state=stopped, residue_after_stop=0
且每 case 至少 --expect-trials 条 certified trial。

退出码非零暴露任何失败。
用法：python3 tools/verify_certification.py reports/runtime_trials.jsonl \
      [--expect-trials 2] [--mvp]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trials_file", nargs="?", default="reports/runtime_trials.jsonl")
    ap.add_argument("--expect-trials", type=int, default=2)
    ap.add_argument("--mvp", action="store_true")
    args = ap.parse_args()
    p = Path(args.trials_file)
    if not p.exists():
        print(f"missing {p}", file=sys.stderr)
        sys.exit(2)
    rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    if not rows:
        print("empty trials file", file=sys.stderr)
        sys.exit(2)
    by_case = {}
    for tr in rows:
        by_case.setdefault(tr["case_id"], []).append(tr)
    failures = []
    n_cert = 0
    for cid, trials in sorted(by_case.items()):
        ok_n = sum(1 for t in trials if trial_ok(t))
        n_cert += ok_n
        if ok_n < args.expect_trials:
            # 收集失败原因
            reasons = set()
            for t in trials:
                if t.get("status") != "certified":
                    for k in ("v0", "v1"):
                        g = t.get(k, {})
                        if g.get("error"):
                            reasons.add(f"{k}:{g['error']}")
                        else:
                            for f in ("seed_outcome", "wrong_outcome", "stale_outcome",
                                      "residual_outcome", "stop_state", "residue_after_stop"):
                                v = g.get(f)
                                if f == "residue_after_stop" and v == 0:
                                    continue
                                if f in ("stale_outcome",) and v is None:
                                    continue
                                if f == "stop_state" and v == "stopped":
                                    continue
                                if v not in (None, "effect_observed" if f in
                                            ("seed_outcome", "residual_outcome") else
                                            "effect_not_observed" if f in
                                            ("wrong_outcome", "stale_outcome") else None):
                                    pass
            failures.append({"case_id": cid, "certified_trials": ok_n,
                             "expected": args.expect_trials,
                             "total_trials": len(trials)})
    print(f"cases: {len(by_case)}  certified cases: "
          f"{sum(1 for c in failures if False) or len(by_case) - len(failures)}  "
          f"certified trials: {n_cert}")
    if failures:
        for f in failures[:20]:
            print(f"  NOT certified: {f['case_id']} ({f['certified_trials']}/{f['expected']} trials)")
        print(f"verify_certification: FAILED ({len(failures)} cases below threshold)")
        sys.exit(1)
    print("verify_certification: PASSED")


if __name__ == "__main__":
    main()
