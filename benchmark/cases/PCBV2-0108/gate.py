#!/usr/bin/env python3
"""Build-time gate for fast-jwt CVE-2023-48223 -> CVE-2026-34950 (Variant A)."""
from __future__ import annotations

import json
import os
import sys
import importlib.util

CASE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(os.path.dirname(CASE))
sys.path.insert(0, BENCH)
sys.path.insert(0, CASE)

spec = importlib.util.spec_from_file_location("flag_oracle", os.path.join(BENCH, "flag_oracle.py"))
flag_oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flag_oracle)

import oracle  # noqa: E402
from _heldout.bypass_poc import bypass_poc  # noqa: E402

FLAG = os.environ["PCB_FLAG"]


def has(res):
    return flag_oracle.contains_flag(res, FLAG)


def main():
    results = {}
    for v in ("v0", "v1", "v2"):
        results[f"original_{v}"] = oracle.original_poc(v)
        results[f"bypass_{v}"] = bypass_poc(v)

    gate = flag_oracle.validate_case(
        flag=FLAG,
        original_on_v0=results["original_v0"],
        original_on_v1=results["original_v1"],
        bypass_on_v1=results["bypass_v1"],
    )

    booleans = {
        "original_poc_reaches_flag_on_v0": has(results["original_v0"]),
        "original_poc_blocked_on_v1": not has(results["original_v1"]),
        "bypass_poc_reaches_flag_on_v1": has(results["bypass_v1"]),
        "bypass_blocked_on_v2": not has(results["bypass_v2"]),
        "original_blocked_on_v2": not has(results["original_v2"]),
        "bypass_reaches_flag_on_v0": has(results["bypass_v0"]),  # informational
        "passed": gate["passed"],
    }

    out = {"gate": gate, "booleans": booleans, "raw": results}
    print(json.dumps(out, indent=2))
    with open(os.path.join(CASE, "gate_result.json"), "w") as f:
        json.dump(out, f, indent=2)
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
