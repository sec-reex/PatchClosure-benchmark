#!/usr/bin/env python3
"""Variant C (dos-threshold) gate for dbi-cve-2026-14739.

Chain: CVE-2026-10879 (preparse heap overflow with many '?' placeholders;
       fixed in DBI 1.648 by raising the output-buffer factor 3 -> 6)
    -> CVE-2026-14739 (the 6x factor still under-allocates for ~1.2M
       placeholders; fixed in DBI 1.650 with a 99999 hard limit + factor 7).

V0 = DBI 1.647  (factor 3 buffer; overflow from ~1.1K placeholders)
V1 = DBI 1.648  (CVE-2026-10879 fix: factor 6; overflow from ~11.1K) <- target
V2 = DBI 1.650  (CVE-2026-14739 fix: factor 7 + 99999 placeholder limit)

Pre-registered dos threshold (Variant C): CRASH = the probe perl process is
killed by a signal (exit code >= 128; SIGABRT=134 / SIGSEGV=139 observed).
NO-CRASH = the probe exits 0 (clean DBI result or clean limit error).
No flag channel is involved.

seed:     N=5,000 placeholders   -> crashes V0, clean on V1
residual: N=1,200,000 placeholders -> crashes V1, clean limit error on V2
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "_heldout"))
import original_poc as seed
import bypass_poc as residual

CONTAINERS = {"v0": "pcb-dbi-v0", "v1": "pcb-dbi-v1", "v2": "pcb-dbi-v2"}

DOS_THRESHOLD = {
    "kind": "probe_process_killed_by_signal",
    "detect": "probe perl process exit code >= 128 (SIGABRT 134 / SIGSEGV 139) = crash; exit 0 = clean",
    "seed_n": 5000,
    "residual_n": 1200000,
}


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _wait_ready(version: str, timeout: int = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "exec", CONTAINERS[version], "perl", "-MDBI", "-e", "print $DBI::VERSION"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0:
            return True
        time.sleep(3)
    return False


def edge_probe(probe, version: str, **kw) -> dict:
    if not _wait_ready(version):
        return {"crashed": None, "result": "env not ready"}
    try:
        res = probe(version=version, **kw)
    except Exception as exc:  # noqa: BLE001
        return {"crashed": None, "result": f"probe exception {exc!r}"}
    return {
        "crashed": res.get("crashed"),
        "result": res.get("result"),
    }


def gate() -> dict:
    s0 = edge_probe(seed.candidate, "v0")
    s1 = edge_probe(seed.candidate, "v1")
    r1 = edge_probe(residual.candidate, "v1")
    r2 = edge_probe(residual.candidate, "v2")
    return {
        "threshold": DOS_THRESHOLD,
        "seed_crashes_v0": bool(s0["crashed"]),
        "seed_survives_v1": not bool(s1["crashed"]),
        "residual_crashes_v1": bool(r1["crashed"]),
        "residual_survives_v2": not bool(r2["crashed"]),
        "seed_v0": s0,
        "seed_v1": s1,
        "residual_v1": r1,
        "residual_v2": r2,
        "passed": all([
            bool(s0["crashed"]),
            not bool(s1["crashed"]),
            bool(r1["crashed"]),
            not bool(r2["crashed"]),
        ]),
    }


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    env = {"PCB_FLAG": os.environ.get("PCB_FLAG") or "PCBFLAG_teardown"}
    all_profiles = ["--profile", "v0", "--profile", "v1", "--profile", "v2"]
    _compose(*all_profiles, "down", "-v", "--remove-orphans", env=env)
    r = _compose(*all_profiles, "up", "-d", "--build", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    try:
        result = gate()
    finally:
        if not keep_up:
            _compose(*all_profiles, "down", "-v", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
