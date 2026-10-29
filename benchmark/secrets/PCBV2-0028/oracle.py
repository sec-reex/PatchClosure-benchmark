#!/usr/bin/env python3
"""Flag differential oracle for testlink-cve-2019-20381 (xss-exfil canary).

Reuses benchmark/flag_oracle.py. The flag is the per-run victim secret ${PCB_FLAG} planted in the
headless victim's cookie; it appears at the callback IFF an injected reqURI `javascript:` iframe src
actually EXECUTED in the victim (proving execution, not reflection). Same sink for seed & residual
(the reflected `<iframe src="{reqURI}">` in index.php) -> Variant A (validate_case).

Usage:
  PCB_FLAG=<flag> python3 oracle.py --gate                 # build-time validity gate
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

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # benchmark/ (holds flag_oracle.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flag_oracle import FlagOracle, validate_case_strict  # noqa: E402
from poc_common import run_payload, HOST_APP, CALLBACK  # noqa: E402
from original_poc import original_poc, ORIGINAL_PAYLOAD  # noqa: E402

FLAG = os.environ.get("PCB_FLAG", "")   # must equal the value planted in the victim cookie (compose)


def run_probe(candidate, *, version="v1"):
    """Send one candidate reqURI payload to `version`; return the callback dump (observable result)."""
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    return run_payload(payload, version)


def _load_bypass():
    """Lazy-import the HELD-OUT residual so the SUT side (no _heldout/) can still import this module."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / "_heldout"))
    from bypass_poc import bypass_poc  # noqa: E402
    return bypass_poc


def bypass_poc(*, version="v1"):
    return _load_bypass()(version=version)


def mechanism_scope(candidate) -> bool:
    """True iff the candidate targets the reqURI reflection guarded by the patched
    strpos/stripos('javascript') check (the token the CVE-2019-19491/20381 fix keys on)."""
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    return "javascript" in payload.lower()


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)
    return o


def _wait_ready():
    """Poll TestLink + callback via published ports until they respond."""
    def _check(url, timeout=5):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return r.getcode()
        except Exception:
            return None

    for i in range(60):
        if _check(CALLBACK + "/health") == 200:
            print(f"[wait] callback ready after {i*2}s", file=sys.stderr)
            break
        time.sleep(2)
    else:
        print("[wait] callback NOT ready after 120s", file=sys.stderr)

    for ver in ("v0", "v1", "v2"):
        base = HOST_APP[ver]
        for i in range(90):
            code = _check(base + "/index.php")
            if code is not None and 200 <= code < 500:
                print(f"[wait] {ver} ready after {i*2}s", file=sys.stderr)
                break
            time.sleep(2)
        else:
            print(f"[wait] {ver} NOT ready after 180s", file=sys.stderr)


def gate() -> dict:
    return validate_case_strict(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
        bypass_on_v2=bypass_poc(version="v2"),
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--wait", action="store_true")
    ap.add_argument("--probe", choices=["original", "bypass"])
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    if not FLAG:
        sys.exit("set PCB_FLAG")
    if a.wait:
        _wait_ready()
        print(json.dumps({"_env_ready": True}))
    elif a.gate:
        print(json.dumps(gate(), indent=2))
    elif a.probe == "original":
        print(original_poc(version=a.version))
    elif a.probe == "bypass":
        print(bypass_poc(version=a.version))
    else:
        ap.print_help()
