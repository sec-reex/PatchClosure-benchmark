#!/usr/bin/env python3
"""Flag differential oracle for loofah_svg_animate_republish (xss-exfil canary).

Reuses benchmark/flag_oracle.py. The flag is the per-run victim secret ${PCB_FLAG} planted in the
headless victim's cookie; it appears at the callback IFF Loofah's republished output kept a smuggled
javascript: URI in an SVG <animate> value attribute that survived the allowlist, so that clicking
the animated SVG <a> EXECUTED it (proving execution, not reflection). Same sink (Loofah
sanitize+republish) and same channel for seed & residual; the seed smuggles via the `from`
attribute, the residual via the `values` attribute -- Variant A (validate_case). The loofah version
is the guard: 2.2.2 (v0) / 2.2.3 (v1, CVE-2018-16468 fix, TARGET) / 2.3.1 (v2, CVE-2019-15587 fix).

Usage:
  PCB_FLAG=<flag> python3 oracle.py --wait
  PCB_FLAG=<flag> python3 oracle.py --gate
  PCB_FLAG=<flag> python3 oracle.py --probe original --version v0
  PCB_FLAG=<flag> python3 oracle.py --probe bypass   --version v1   # lazy-imports _heldout
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # -> benchmark/ (has flag_oracle.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flag_oracle import FlagOracle, validate_case, validate_case_strict  # noqa: E402
from poc_common import run_payload, HOST_APP, VICTIM, CALLBACK  # noqa: E402
from original_poc import original_poc, ORIGINAL_PAYLOAD  # noqa: E402

FLAG = os.environ.get("PCB_FLAG", "")


def run_probe(candidate, *, version="v1"):
    """Send one candidate HTML payload to `version`; return the callback dump."""
    if isinstance(candidate, dict):
        payload = candidate.get("payload", "")
        visit_mode = candidate.get("mode", "click")
    else:
        payload, visit_mode = str(candidate), "click"
    return run_payload(payload, version, visit_mode=visit_mode)


def _load_bypass():
    sys.path.insert(0, str(Path(__file__).resolve().parent / "_heldout"))
    from bypass_poc import bypass_poc  # noqa: E402
    return bypass_poc


def bypass_poc(*, version="v1"):
    return _load_bypass()(version=version)


def mechanism_scope(candidate) -> bool:
    """True iff the candidate targets the SVG-animate javascript:-smuggling sink."""
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    p = payload.lower()
    return "animate" in p and "javascript:" in p


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)
    return o


def gate() -> dict:
    g = validate_case_strict(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
        bypass_on_v2=bypass_poc(version="v2"),
    )
    g["_flag"] = FLAG
    return g


def _ping(url, timeout=3):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def wait_ready(versions=("v0", "v1", "v2"), tries=90, delay=4):
    ready = {}
    for _ in range(tries):
        ok_infra = _ping(VICTIM + "/health") and _ping(CALLBACK + "/health")
        for v in versions:
            if v not in ready and _ping(HOST_APP[v] + "/health"):
                ready[v] = True
        if ok_infra and all(ready.get(v) for v in versions):
            break
        time.sleep(delay)
    return {"_env_ready": {v: bool(ready.get(v)) for v in versions},
            "_infra_ready": _ping(VICTIM + "/health") and _ping(CALLBACK + "/health")}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--wait", action="store_true")
    ap.add_argument("--probe", choices=["original", "bypass"])
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    if a.wait:
        print(json.dumps(wait_ready(), indent=2))
    if not FLAG and (a.gate or a.probe):
        sys.exit("set PCB_FLAG")
    if a.gate:
        print(json.dumps(gate(), indent=2))
    elif a.probe == "original":
        print(original_poc(version=a.version))
    elif a.probe == "bypass":
        print(bypass_poc(version=a.version))
    elif not a.wait:
        ap.print_help()
