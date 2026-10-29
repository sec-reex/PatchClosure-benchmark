#!/usr/bin/env python3
"""verify_source_immutability: prove the benchmark corpus did not change between
the baseline snapshot and now.

语料 = 本树（benchmark/）：cases/<eval_id>/ 同时带学术 case.json 与平台 case.yaml/scripts；
V2 held-out 评测物料在 benchmark/v2_harness/（2026-09-29 清理后并入本树）。
易变面（平台每次 run 都会写）不参与证明：work/、reports/。

  verify_source_immutability.py --snapshot   # 重新基线（发布/清理后）
  verify_source_immutability.py              # 与基线比对，任何漂移 → 非零
"""
import hashlib
import json
import os
import sys
from pathlib import Path

TREE = Path(__file__).resolve().parents[1]   # benchmark/（语料树根）
BASELINE = TREE / "reports" / "source_tree_baseline.sha256"
AFTER = TREE / "reports" / "source_tree_after.sha256"

# 平台运行会写：不参与不变性证明
VOLATILE_TOP = {"work", "reports", "__pycache__", ".pytest_cache"}


def tree_hash(root: Path) -> dict:
    out = {}
    for dp, dirnames, fs in os.walk(root):
        rel_dir = Path(dp).relative_to(root)
        if rel_dir.parts and rel_dir.parts[0] in VOLATILE_TOP:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git")]
        for fn in sorted(fs):
            if fn == ".DS_Store":
                continue
            p = Path(dp) / fn
            if p.is_symlink():
                continue
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def main() -> int:
    snapshot = "--snapshot" in sys.argv
    after = tree_hash(TREE)
    if snapshot:
        BASELINE.write_text(json.dumps(after, indent=1, sort_keys=True))
        print(f"baseline written: {BASELINE} ({len(after)} files)")
        return 0
    before = json.loads(BASELINE.read_text())
    AFTER.write_text(json.dumps(after, indent=1, sort_keys=True))
    changed = [rel for rel in sorted(set(before) | set(after)) if before.get(rel) != after.get(rel)]
    if changed:
        print("CORPUS CHANGED:")
        for c in changed[:50]:
            print(" ", c)
        sys.exit(1)
    print(f"corpus immutable: benchmark/ unchanged vs baseline ({len(after)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
