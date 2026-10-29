#!/usr/bin/env python3
"""Flag differential oracle for openssl-c_rehash-shell-metachar-incomplete.

Reuses benchmark/flag_oracle.py (Variant A). Each version image compiles the REAL OpenSSL
release from source and installs the REAL c_rehash + openssl (no lifted script, no stub).
A probe seeds a directory with ONE certificate file whose NAME carries a benign shell-metachar
payload (`echo $PCB_FLAG>relfile`) and runs the REAL `c_rehash <dir>`; if the command-injection
at that version's call site fires, the flag lands in the probe's stdout.

NOTE: this sink is a CLI / command-injection vector, NOT an HTTP endpoint. run_mode is
"real-cli-nonhttp": the real external trigger is invoking the real c_rehash binary on a
directory that holds an attacker-controlled certificate FILENAME.

Roles (SPEC.md):
  V0 = real OpenSSL 1.1.1n c_rehash  (CVE-2022-1292 present)
  V1 = real OpenSSL 1.1.1o c_rehash  (CVE-2022-1292 fixed, INCOMPLETELY -> CVE-2022-2068)  <- target
  V2 = real OpenSSL 1.1.1p c_rehash  (CVE-2022-2068 fixed)

Usage:
  python3 oracle.py --run-gate --matrix   # build images, run gate + full 3x2 matrix, print JSON
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case, validate_case_strict  # noqa: E402
sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

PROFILE_OF = {"v0": "v0", "v1": "v1", "v2": "v2"}


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False, env={**os.environ, **(env or {})},
    )


def run_probe(candidate, *, version="v1"):
    """Run the REAL c_rehash for `version` against a dir seeded with the candidate's
    malicious cert filename. Returns {version, flavor, stdout, stderr}."""
    flavor = candidate["flavor"] if isinstance(candidate, dict) else str(candidate)
    prof = PROFILE_OF[version]
    r = _compose("--profile", prof, "run", "--rm", version, flavor, env={"PCB_FLAG": FLAG})
    return {"version": version, "flavor": flavor, "stdout": r.stdout, "stderr": r.stderr}


def original_poc(*, version="v1"):
    return run_probe(original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return run_probe(mod.candidate(), version=version)


def mechanism_scope(candidate) -> bool:
    """True iff the candidate exercises the c_rehash certificate-filename shell sink."""
    flavor = candidate.get("flavor", "") if isinstance(candidate, dict) else str(candidate)
    return flavor in ("original", "residual")


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


def _build():
    return _compose("--profile", "v0", "--profile", "v1", "--profile", "v2",
                    "build", env={"PCB_FLAG": FLAG})


def run_gate(matrix=False) -> dict:
    global FLAG
    FLAG = new_flag()
    b = _build()
    if b.returncode != 0:
        return {"error": "build failed", "stderr": b.stderr[-4000:], "stdout": b.stdout[-2000:]}
    result = gate()
    if matrix:
        full = {}
        for v in ("v0", "v1", "v2"):
            for fl in ("original", "residual"):
                res = run_probe({"flavor": fl}, version=v)
                full[f"{v}/{fl}"] = "FLAG" if FLAG in res["stdout"] else "blocked"
        result["_matrix"] = full
    result["_flag"] = FLAG
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--matrix", action="store_true", help="also print the full 3x2 fire/blocked matrix")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(matrix=a.matrix), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
