#!/usr/bin/env python3
"""Flag differential oracle for siyuan-cve-2026-31807 (xss-exfil canary).

Chain: CVE-2026-29183 (reflected XSS via getDynamicIcon type=8, SanitizeSVG added 3.5.9)
     -> CVE-2026-31807 (SVG animate element bypass, fixed 3.5.10).

V0 = SiYuan 3.5.8 (RemoveScriptsInSVG: <script> only)
V1 = SiYuan 3.5.9 (SanitizeSVG: strips javascript: href, but not java\\rscript:)  <- target
V2 = SiYuan 3.5.10 (strips CR before scheme check)

The headless victim (victim.py, via the selenium grid) carries PCB_FLAG in the siyuan
cookie, loads the attacker SVG, clicks the anchor; the javascript: URL exfiltrates
document.cookie to the internal callback. The oracle triggers the visit and reads /dump.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case_strict  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as seed_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

VICTIM = 56871
CALLBACK = 56891


def run_probe(candidate, *, version="v1"):
    """Trigger one victim visit and read the callback dump."""
    target = candidate["target"]
    origin = candidate["origin"]
    subprocess.run(["curl", "-s", f"http://127.0.0.1:{CALLBACK}/reset"], capture_output=True)
    visit_url = (f"http://127.0.0.1:{VICTIM}/visit?target="
                 + urllib.parse.quote(target, safe="") + "&origin=" + urllib.parse.quote(origin, safe=""))
    try:
        urllib.request.urlopen(visit_url, timeout=60).read()
    except Exception:
        pass
    time.sleep(1)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{CALLBACK}/dump", timeout=10) as r:
            hits = json.loads(r.read().decode())
    except Exception:
        hits = []
    return {"status": 200, "body": "\n".join(hits)}


def original_poc(*, version="v1"):
    base = {"v0": "http://v0:6806", "v1": "http://v1:6806", "v2": "http://v2:6806"}[version]
    return run_probe(seed_candidate(base=base), version=version)


def bypass_poc(*, version="v1"):
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    base = {"v0": "http://v0:6806", "v1": "http://v1:6806", "v2": "http://v2:6806"}[version]
    return run_probe(mod.candidate(base=base), version=version)


def mechanism_scope(candidate) -> bool:
    return "getDynamicIcon" in candidate.get("target", "")


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)
    return o


def gate() -> dict:
    return validate_case_strict(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
        bypass_on_v2=bypass_poc(version="v2"),
    )


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _wait_ready(version: str, tries: int = 60) -> bool:
    port = {"v0": 56830, "v1": 56831, "v2": 56832}[version]
    for _ in range(tries):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/icon/getDynamicIcon?type=8&content=H", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def _profile_flags(profiles):
    flags = []
    for p in profiles:
        flags += ["--profile", p]
    return flags


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(("v0", "v1", "v2"))
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*_profile_flags(("v0", "v1", "v2")), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:], "stdout": r.stdout[-2000:]}
    ready = {v: _wait_ready(v) for v in profiles}
    # wait for victim (pip-installs selenium on first start) + grid
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{VICTIM}/health", timeout=5) as r:
                if r.status == 200:
                    break
        except Exception:
            pass
        time.sleep(3)
    time.sleep(2)
    result = gate()
    result["_env_ready"] = ready
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
