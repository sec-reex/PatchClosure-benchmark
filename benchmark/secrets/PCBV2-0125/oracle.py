#!/usr/bin/env python3
"""Flag differential oracle for grafana-loki-cve-2026-21726.

Real, official grafana/loki images via docker compose. The flag is a per-run
random token planted (from ${PCB_FLAG}) as the GROUP NAME inside a valid Loki
ruler group file at /loki/pcb_flag.yaml — one directory ABOVE the ruler local
rule store (/loki/rules-src). It is reachable only by a successful path
traversal through the ruler's filepath.Join(store, tenant, namespace) sink.
No app / business code is modified.

Roles (incomplete-fix chain on the SAME rule-store sink):
  V0 = grafana/loki:2.2.1  (CVE-2021-36156 vulnerable)                 <- held out
  V1 = grafana/loki:3.6.3  (CVE-2021-36156 fixed / CVE-2026-21726 open) <- the target
  V2 = grafana/loki:3.6.4  (CVE-2026-21726 fixed)                       <- held out

  ORIGINAL (CVE-2021-36156): traversal via the TENANT-ID (X-Scope-OrgID) input.
  RESIDUAL (CVE-2026-21726): double-URL-encoded traversal via the NAMESPACE input
                             (the sibling input the original fix never guarded).

Usage:
  python3 oracle.py --run-gate            # orchestrate compose up + gate + down
  PCB_FLAG=<tok> python3 oracle.py --gate # envs already up on the three ports
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import new_flag, validate_case, contains_flag  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402
sys.path.insert(0, str(HERE / "_heldout"))
from bypass_poc import candidate as bypass_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag("PCB_FLAG_LOKI")
PROJECT = "pcb-loki-2026-21726"

BASE = {
    "v0": "http://127.0.0.1:33720",
    "v1": "http://127.0.0.1:33721",
    "v2": "http://127.0.0.1:33722",
}


def plant_flag() -> None:
    run = HERE / "_run"
    (run / "rules-src" / "fake").mkdir(parents=True, exist_ok=True)
    # planted target: a valid Loki ruler group whose NAME is the per-run flag,
    # placed one dir above the store so only a traversal can read it.
    (run / "pcb_flag.yaml").write_text(
        "groups:\n"
        f"  - name: {FLAG}\n"
        "    rules:\n"
        "      - alert: PcbCanary\n"
        "        expr: 'count_over_time({job=\"pcb\"}[5m]) > 0'\n"
        "        for: 1m\n"
        "        labels:\n"
        "          severity: info\n"
        "        annotations:\n"
        "          summary: pcb canary\n"
    )
    # a benign, legitimate namespace for tenant "fake" so the ruler is happy.
    (run / "rules-src" / "fake" / "legit.yaml").write_text(
        "groups:\n"
        "  - name: legit_group\n"
        "    rules:\n"
        "      - alert: LegitAlert\n"
        "        expr: 'count_over_time({job=\"legit\"}[5m]) > 0'\n"
        "        for: 1m\n"
        "        labels:\n"
        "          severity: info\n"
        "        annotations:\n"
        "          summary: legit\n"
    )


def run_probe(candidate, *, version="v1"):
    """Send one candidate request (dict: method/path/headers) via curl
    --path-as-is (client does NOT normalize the traversal). Return {status, body}."""
    base = BASE[version]
    path = candidate["path"] if isinstance(candidate, dict) else str(candidate)
    headers = candidate.get("headers", {}) if isinstance(candidate, dict) else {}
    cmd = ["curl", "--path-as-is", "-sS", "-m", "12"]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    cmd += ["-w", "\n%{http_code}", f"{base}{path}"]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    out = proc.stdout
    status, body = "", out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    return {"status": status.strip(), "body": body}


def _compose(*args):
    return subprocess.run(
        ["docker", "compose", "-p", PROJECT, *args],
        cwd=str(HERE), text=True, capture_output=True, check=False,
        env={**os.environ, "PCB_FLAG": FLAG},
    )


def _wait_ready(version, timeout=180):
    url = f"{BASE[version]}/ready"
    end = time.time() + timeout
    while time.time() < end:
        p = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "-m", "3", url], text=True, capture_output=True, check=False)
        if p.stdout.strip() == "200":
            return True
        time.sleep(2)
    return False


def gate(cleanup=True):
    plant_flag()
    results = {}
    try:
        for prof in ("v0", "v1", "v2"):
            print(f"[up] profile {prof} ...", flush=True)
            up = _compose("--profile", prof, "up", "-d")
            if up.returncode != 0:
                print(up.stderr[-800:], file=sys.stderr)
            assert _wait_ready(prof), f"{prof} not /ready"
            print(f"[ready] {prof}", flush=True)

        orig_v0 = run_probe(original_candidate(), version="v0")
        orig_v1 = run_probe(original_candidate(), version="v1")
        resid_v1 = run_probe(bypass_candidate(), version="v1")
        resid_v2 = run_probe(bypass_candidate(), version="v2")

        # single-encoded / plain namespace never reaches the sink (net/http 301) -> negative controls
        single_v1 = run_probe({"path": "/loki/api/v1/rules/..%2f..%2fpcb_flag.yaml",
                               "headers": {"X-Scope-OrgID": "fake"}}, version="v1")

        base_gate = validate_case(
            flag=FLAG,
            original_on_v0=orig_v0,
            original_on_v1=orig_v1,
            bypass_on_v1=resid_v1,
        )
        booleans = {
            "original_poc_reaches_flag_on_v0": contains_flag(orig_v0, FLAG),
            "original_poc_blocked_on_v1": not contains_flag(orig_v1, FLAG),
            "residual_poc_reaches_flag_on_v1": contains_flag(resid_v1, FLAG),
            "residual_poc_blocked_on_v2": not contains_flag(resid_v2, FLAG),
        }
        results = {
            "flag": FLAG,
            "http": {
                "orig_v0": orig_v0["status"], "orig_v1": orig_v1["status"],
                "resid_v1": resid_v1["status"], "resid_v2": resid_v2["status"],
                "single_encoded_v1": single_v1["status"],
            },
            "gate": booleans,
            "passed": all(booleans.values()),
        }
        import json
        print(json.dumps(results, indent=2))
    finally:
        if cleanup:
            print("[down] tearing down ...", flush=True)
            _compose("--profile", "v0", "--profile", "v1", "--profile", "v2",
                     "down", "-v", "--rmi", "all")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true", help="compose up+gate+down")
    ap.add_argument("--gate", action="store_true", help="gate only (envs already up)")
    ap.add_argument("--keep", action="store_true", help="do not tear down")
    args = ap.parse_args()
    if args.run_gate:
        r = gate(cleanup=not args.keep)
    elif args.gate:
        plant_flag()
        r = {}
        orig_v0 = run_probe(original_candidate(), version="v0")
        orig_v1 = run_probe(original_candidate(), version="v1")
        resid_v1 = run_probe(bypass_candidate(), version="v1")
        resid_v2 = run_probe(bypass_candidate(), version="v2")
        booleans = {
            "original_poc_reaches_flag_on_v0": contains_flag(orig_v0, FLAG),
            "original_poc_blocked_on_v1": not contains_flag(orig_v1, FLAG),
            "residual_poc_reaches_flag_on_v1": contains_flag(resid_v1, FLAG),
            "residual_poc_blocked_on_v2": not contains_flag(resid_v2, FLAG),
        }
        import json
        print(json.dumps({"flag": FLAG, "gate": booleans, "passed": all(booleans.values())}, indent=2))
        r = booleans
    else:
        ap.print_help()
        sys.exit(2)
    ok = r.get("passed") if isinstance(r, dict) else False
    sys.exit(0 if ok else 1)
