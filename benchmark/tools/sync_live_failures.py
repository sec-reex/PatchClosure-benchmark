#!/usr/bin/env python3
"""Sync live-sweep FAILED rows into reports/LIVE_SWEEP_FAILURES.{jsonl,md}.

A case is recorded iff compose-up + exp (platform start → verify seed/residual)
did not certify. Do not delete entries; later passes may append a newer line.
"""
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
JSONL = REPORTS / "LIVE_SWEEP_FAILURES.jsonl"
MD = REPORTS / "LIVE_SWEEP_FAILURES.md"


def load_known():
    seen = {}
    if JSONL.exists():
        for line in JSONL.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            seen[rec["case_id"]] = rec
    return seen


def clip(s, n=240):
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 3] + "..."


def summarize(rec):
    v0 = rec.get("v0") or {}
    v1 = rec.get("v1") or {}
    v0s = v0.get("seed_outcome") or clip(v0.get("error"), 80) or "?"
    v1s = v1.get("seed_outcome") or clip(v1.get("error"), 80) or "?"
    v1r = v1.get("residual_outcome") or ""
    err = clip(v0.get("error") or v1.get("error") or "")
    why = "start_or_exp_failed"
    blob = (str(v0.get("error") or "") + " " + str(v1.get("error") or "")).lower()
    if "startup_error" in blob or "start rc=" in blob:
        why = "compose_up_failed"
    elif "environment_failure" in str(v0s) or "environment_failure" in str(v1s):
        why = "exp_environment_failure"
    elif v0.get("seed_outcome") == "effect_observed" and v1.get("seed_outcome") != "effect_not_observed":
        why = "v1_seed_not_blocked"
    elif v1.get("residual_outcome") not in (None, "effect_observed") and v1.get("seed_outcome") == "effect_not_observed":
        why = "v1_residual_missed"
    return {
        "case_id": rec.get("case_id"),
        "status": rec.get("status", "failed"),
        "why": why,
        "v0_seed": v0s,
        "v1_seed": v1s,
        "v1_residual": v1r,
        "error": err,
        "trial_no": rec.get("trial_no"),
    }


def collect():
    rows = {}
    for p in sorted(REPORTS.glob("live215_group*.jsonl")):
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("status") == "certified":
                continue
            rows[rec["case_id"]] = summarize(rec)
    # progress-only FAILED with no jsonl body
    for p in sorted(REPORTS.glob("live215_group*.jsonl.progress")):
        for line in p.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            cid, st = parts[0], parts[1]
            if st == "FAILED" and cid not in rows:
                rows[cid] = {
                    "case_id": cid,
                    "status": "failed",
                    "why": "start_or_exp_failed",
                    "v0_seed": "",
                    "v1_seed": "",
                    "v1_residual": "",
                    "error": "\t".join(parts[2:]),
                    "trial_no": None,
                }
    return rows


def write_md(rows):
    lines = [
        "# LIVE_SWEEP_FAILURES",
        "",
        "Cannot `compose up` (via start.sh) then exp/verify successfully.",
        "Record only — do not fix in this sweep. Waiting for a later pass.",
        "",
        f"Count: **{len(rows)}**",
        "",
        "| case | why | v0 seed | v1 seed | v1 residual | error |",
        "|---|---|---|---|---|---|",
    ]
    for cid in sorted(rows):
        r = rows[cid]
        lines.append(
            f"| {cid} | {r.get('why','')} | {r.get('v0_seed','')} | {r.get('v1_seed','')} | {r.get('v1_residual','')} | {clip(r.get('error'), 160)} |"
        )
    MD.write_text("\n".join(lines) + "\n")


def sync_once():
    known = load_known()
    now = collect()
    new = []
    for cid, rec in sorted(now.items()):
        prev = known.get(cid)
        if prev and prev.get("why") == rec.get("why") and prev.get("error") == rec.get("error"):
            continue
        with JSONL.open("a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        known[cid] = rec
        new.append(cid)
    write_md(known)
    return len(known), new


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--interval", type=int, default=30)
    args = ap.parse_args()
    n, new = sync_once()
    print(f"failures={n} new={new or '-'}", flush=True)
    if not args.watch:
        return
    while True:
        time.sleep(args.interval)
        n, new = sync_once()
        if new:
            print(f"failures={n} new={new}", flush=True)


if __name__ == "__main__":
    main()
