#!/usr/bin/env python3
"""Flag differential oracle for antisamy_style_smuggling (xss-exfil canary).

Reuses benchmark/flag_oracle.py. The flag is the per-run victim secret ${PCB_FLAG} planted in the
headless victim's cookie; it appears at the callback IFF AntiSamy's SANITIZED output still smuggled a
live element that EXECUTED in the browser (proving execution, not reflection). Same sink
(`new AntiSamy().scan(html, antisamy.xml, DOM).getCleanHTML()`) and same channel for seed & residual;
only the smuggled-child count differs -> Variant A (validate_case). The AntiSamy version is the guard:
1.6.5 (v0) / 1.6.6 (v1, CVE-2022-28367 PARTIAL fix, TARGET) / 1.6.7 (v2, CVE-2022-29577 COMPLETE fix).

Usage:
  PCB_FLAG=<flag> python3 oracle.py --wait                       # wait until v0/v1/v2 envs are ready
  PCB_FLAG=<flag> python3 oracle.py --gate                       # build-time validity gate
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

FLAG = os.environ.get("PCB_FLAG", "")   # must equal the value planted in the victim cookie (compose)


def run_probe(candidate, *, version="v1"):
    """Send one candidate HTML payload to `version`; return the callback dump."""
    if isinstance(candidate, dict):
        payload = candidate.get("payload", "")
        mode = candidate.get("mode", "load")
    else:
        payload, mode = str(candidate), "load"
    return run_payload(payload, version, mode)


def _load_bypass():
    """Lazy-import the HELD-OUT residual so the SUT side (no _heldout/) can still import this module."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / "_heldout"))
    from bypass_poc import bypass_poc  # noqa: E402
    return bypass_poc


def bypass_poc(*, version="v1"):
    return _load_bypass()(version=version)


def mechanism_scope(candidate) -> bool:
    """True iff the candidate targets the AntiSamy STYLE-smuggling sink (an event handler/script/js sink)."""
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    p = payload.lower()
    return ("onerror" in p or "onload" in p or "onfocus" in p or "onmouseover" in p
            or "<script" in p or "javascript:" in p) and "style" in p


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


def wait_ready(versions=("v0", "v1", "v2"), tries=120, delay=4):
    """Poll app /health + victim/callback /health until ready (canary-detected = ready)."""
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
