#!/usr/bin/env python3
"""Generate the Round-24 platform reports from current state:
  platform_inventory.json
  migration_report.json
  oracle_family_matrix.csv
  source_materialization_report.jsonl
  certification_summary.md
  unready_cases.json
  api_smoke_test.txt
"""
import csv
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

TREE = Path(__file__).resolve().parents[1]   # benchmark/（合并树根）
OUT = TREE / "reports"
CASES = TREE / "cases"
WORK = TREE / "work"
DB = WORK / "state" / "platform.db"


def load_cases():
    out = {}
    for d in sorted((CASES).iterdir()):
        p = d / "platform_case.json"
        if p.exists():
            out[d.name] = json.loads(p.read_text())
    return out


def load_certification():
    p = OUT / "certification_215.jsonl"
    if p.exists():
        txt = p.read_text()
        if txt.lstrip().startswith("["):
            try:
                return json.loads(txt)
            except Exception:
                return []
        out = []
        for l in txt.splitlines():
            l = l.strip()
            if not l:
                continue
            try:
                out.append(json.loads(l))
            except Exception:
                continue  # partial line while being written
        return out
    p = OUT / "mvp_certification.json"
    if p.exists():
        return json.loads(p.read_text())
    return []


def main():
    cases = load_cases()
    certs = load_certification()
    by_case = {}
    for c in certs:
        by_case.setdefault(c["case_id"], []).append(c)
    cert_status = {cid: (trials[-1].get("status", "unknown") if trials else "unknown")
                   for cid, trials in by_case.items()}

    # 1) platform_inventory.json
    inv = []
    for cid, pc in cases.items():
        inv.append({
            "case_id": cid,
            "real_case_id": pc.get("real_case_id"),
            "run_mode": pc.get("run_mode"),
            "oracle_family": pc.get("oracle_family"),
            "family_derivation": pc.get("family_derivation", {}),
            "certification": cert_status.get(cid, "unknown"),
            "provenance": pc.get("provenance", {}),
        })
    (OUT / "platform_inventory.json").write_text(json.dumps(inv, indent=1, ensure_ascii=False))

    # 2) oracle_family_matrix.csv
    with open(OUT / "oracle_family_matrix.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "real_case_id", "oracle_family", "run_mode", "certification",
                    "family_source"])
        for row in inv:
            w.writerow([row["case_id"], row["real_case_id"], row["oracle_family"],
                        row["run_mode"], row["certification"],
                        row["family_derivation"].get("source", "")])

    # 3) migration_report.json
    overrides = []
    od = TREE / "migrations" / "overrides"
    for f in sorted(od.glob("*.json")):
        overrides.append(json.loads(f.read_text()))
    fam_dist = Counter(r["oracle_family"] for r in inv)
    mig = {
        "generated_at": datetime.now().isoformat(),
        "total_cases": len(inv),
        "oracle_family_distribution": dict(fam_dist),
        "overrides": overrides,
        "certification_status_counts": dict(Counter(r["certification"] for r in inv)),
        "legacy_defects_confirmed": {
            "all_manifests_read_exfil_label": True,
            "evaluator_oracle_py_missing": True,
            "candidate_scoring_readiness": "not_established_pre_platform",
        },
    }
    (OUT / "migration_report.json").write_text(json.dumps(mig, indent=1, ensure_ascii=False))

    # 4) source_materialization_report.jsonl
    n = 0
    with open(OUT / "source_materialization_report.jsonl", "w") as f:
        for rd in sorted((WORK / "runs").glob("*")):
            sm = rd / "source_manifest.json"
            if sm.exists():
                f.write(json.dumps({"run_id": rd.name, **json.loads(sm.read_text())}) + "\n")
                n += 1

    # 5) certification_summary.md
    total = len(inv)
    cnt = Counter(r["certification"] for r in inv)
    with open(OUT / "certification_summary.md", "w") as f:
        f.write("# Round 24 Certification Summary\n\n")
        f.write(f"_generated {datetime.now().isoformat()}_\n\n")
        f.write("| metric | count |\n|---|---:|\n")
        f.write(f"| total cases | {total} |\n")
        f.write(f"| certified_candidate_scoring_ready | {cnt.get('certified_candidate_scoring_ready', 0)} |\n")
        f.write(f"| unready | {cnt.get('unready', 0)} |\n")
        f.write(f"| source_error | {cnt.get('source_error', 0)} |\n")
        f.write(f"| build/startup error | {cnt.get('startup_error', 0)} |\n")
        f.write(f"| readiness_error | {cnt.get('readiness_error', 0)} |\n")
        f.write(f"| reference_failure | {cnt.get('reference_failure', 0)} |\n")
        f.write(f"| scorer_failure | {cnt.get('scorer_failure', 0)} |\n")
        f.write(f"| cleanup_failure | {cnt.get('cleanup_failure', 0)} |\n")
        f.write(f"| unknown | {cnt.get('unknown', 0)} |\n")

    # 6) unready_cases.json
    unready = [r for r in inv if r["certification"] not in ("certified_candidate_scoring_ready",)]
    (OUT / "unready_cases.json").write_text(
        json.dumps(unready, indent=1, ensure_ascii=False))

    print(f"reports written: inventory {len(inv)}, materialization {n} runs, "
          f"unready {len(unready)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
