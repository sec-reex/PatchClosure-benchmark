#!/usr/bin/env python3
"""move_secrets_v2.py — four-role separation move (task book §3.2).

Relocates the 6 answer-class item types out of benchmark/cases/<id>/ into
benchmark/secrets/<id>/ so that cases/ holds only the public definition + environment
and never ships answers to a contestant package.

Mapping (per case, when present):
    cases/<id>/_heldout/                 -> secrets/<id>/_heldout/
    cases/<id>/poc/bypass_poc.py         -> secrets/<id>/bypass_poc.py   (flattened, per §3.1)
    cases/<id>/oracle.py                 -> secrets/<id>/oracle.py
    cases/<id>/gate_result.json          -> secrets/<id>/gate_result.json
    cases/<id>/INCOMPLETE_FIX_ANALYSIS.md-> secrets/<id>/INCOMPLETE_FIX_ANALYSIS.md
    cases/<id>/repro.log                 -> secrets/<id>/repro.log

Before any move, a full byte-copy backup + per-case MANIFEST.md (sha256 + src->dest
mapping) is written to benchmark/replacements_2026-10-12_secrets_move/<id>/.

IDEMPOTENT: an item already moved (absent from cases/, present in secrets/) is skipped.
REVERSIBLE: move each item in secrets/<id>/ back to its cases/<id>/ source path.

Usage:
    python3 benchmark/migrations/move_secrets_v2.py            # dry-run
    python3 benchmark/migrations/move_secrets_v2.py --apply
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
CASES = BENCH / "cases"
SECRETS = BENCH / "secrets"
BACKUP = BENCH / "replacements_2026-10-12_secrets_move"

# (relative-source-in-case, relative-dest-in-secrets)
ITEMS = [
    ("_heldout", "_heldout"),
    ("poc/bypass_poc.py", "bypass_poc.py"),
    ("poc/residual_poc.py", "residual_poc.py"),   # worked residual exploit = answer-class (9 cases)
    ("oracle.py", "oracle.py"),
    ("gate_result.json", "gate_result.json"),
    ("INCOMPLETE_FIX_ANALYSIS.md", "INCOMPLETE_FIX_ANALYSIS.md"),
    ("repro.log", "repro.log"),
]


def sha256_path(p: Path) -> str:
    """sha256 of a file, or of the sorted file-tree for a directory."""
    h = hashlib.sha256()
    if p.is_dir():
        for f in sorted(p.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                h.update(str(f.relative_to(p)).encode())
                h.update(f.read_bytes())
        return "dir:" + h.hexdigest()
    h.update(p.read_bytes())
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    cases = sorted(d.name for d in CASES.iterdir()
                   if d.is_dir() and d.name.startswith("PCBV2-"))
    counts = {dest: 0 for _src, dest in ITEMS}
    moved_total = 0
    skipped_already = 0

    if args.apply:
        BACKUP.mkdir(parents=True, exist_ok=True)
        SECRETS.mkdir(parents=True, exist_ok=True)

    for cid in cases:
        cdir = CASES / cid
        sdir = SECRETS / cid
        man_lines = [f"# secrets-move backup — {cid} — {datetime.date.today().isoformat()}",
                     "", "| item | sha256 | src | dest |", "|---|---|---|---|"]
        case_has_move = False
        for src_rel, dest_rel in ITEMS:
            src = cdir / src_rel
            dest = sdir / dest_rel
            if not src.exists():
                if dest.exists():
                    skipped_already += 1
                continue
            case_has_move = True
            digest = sha256_path(src)
            counts[dest_rel] += 1
            moved_total += 1
            man_lines.append(f"| {src_rel} | {digest} | cases/{cid}/{src_rel} | secrets/{cid}/{dest_rel} |")
            if args.apply:
                # 1) backup copy
                bdst = BACKUP / cid / src_rel
                bdst.parent.mkdir(parents=True, exist_ok=True)
                if src.is_dir():
                    if bdst.exists():
                        shutil.rmtree(bdst)
                    shutil.copytree(src, bdst, ignore=shutil.ignore_patterns("__pycache__"))
                else:
                    shutil.copy2(src, bdst)
                # 2) move original -> secrets
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(src), str(dest))
            else:
                print(f"[DRY] {cid}: {src_rel} -> secrets/{cid}/{dest_rel}  ({digest[:16]})")
        if args.apply and case_has_move:
            (BACKUP / cid).mkdir(parents=True, exist_ok=True)
            man = BACKUP / cid / "MANIFEST.md"
            data_rows = [ln for ln in man_lines if ln.startswith("| ") and not ln.startswith("| item ")]
            if man.exists():
                # append-merge: preserve rows recorded by earlier move runs
                existing = man.read_text()
                new_rows = [r for r in data_rows if r not in existing]
                if new_rows:
                    man.write_text(existing.rstrip("\n") + "\n" + "\n".join(new_rows) + "\n")
            else:
                man.write_text("\n".join(man_lines) + "\n")

    print(f"\n{'APPLIED' if args.apply else 'DRY-RUN'}: moved {moved_total} item(s); "
          f"{skipped_already} already-in-secrets skipped.")
    print("per-type counts:")
    for dest_rel, n in counts.items():
        print(f"  {dest_rel:32} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
