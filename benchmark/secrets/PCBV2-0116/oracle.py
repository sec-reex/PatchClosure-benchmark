#!/usr/bin/env python3
"""Flag differential oracle for git-submodule-url-dash-argument-injection.

Reuses benchmark/flag_oracle.py. The flag is a per-run random canary echoed by a
benign probe (/pcb-probe.sh) that runs ONLY if a leading-dash submodule value is
argument-injected into a child process during `git clone --recurse-submodules`.
Nothing in git's source is modified; the probe + a modeled ssh client are planted
in the environment by victim.sh.

Roles (SPEC.md):
  V0 = git 2.13.4  (vulnerable to CVE-2017-1000117 AND CVE-2018-17456)
  V1 = git 2.14.1  (CVE-2017-1000117 patched in connect.c, INCOMPLETELY ->
                    still vulnerable to CVE-2018-17456)                 <- target
  V2 = git 2.19.1  (CVE-2018-17456 patched in submodule--helper.c; fully fixed)

Usage:
  python3 oracle.py --run-gate            # build images -> plant flag -> gate -> teardown
  python3 oracle.py --run-gate --keep      # keep images after gate
  PCB_FLAG=<tok> python3 oracle.py --gate  # gate against already-built images
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
from flag_oracle import FlagOracle, new_flag, validate_case  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

# git source version compiled into each image (Dockerfile build-arg GIT_VER).
GIT_VER = {"v0": "2.13.4", "v1": "2.14.1", "v2": "2.19.1"}
IMAGE = {v: f"pcb-git:{v}" for v in GIT_VER}
VICTIM = HERE / "victim.sh"


# --------------------------------------------------------------------------- #
# Probe: run one candidate (submodule url/path) inside a version's container.
# --------------------------------------------------------------------------- #
def run_probe(candidate, *, version="v1"):
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    path = candidate.get("path", "sm") if isinstance(candidate, dict) else "sm"
    proc = subprocess.run(
        ["docker", "run", "--rm", "-e", f"PCB_FLAG={FLAG}",
         "-v", f"{VICTIM}:/victim.sh:ro", IMAGE[version],
         "sh", "/victim.sh", url, path],
        text=True, capture_output=True, check=False, timeout=180,
    )
    return {"version": version, "url": url, "path": path,
            "output": proc.stdout + proc.stderr}


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2017-1000117 ssh-host-dash seed. Blocked on v1."""
    return run_probe(original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2018-17456 url-value-dash residual. Imported lazily from
    _heldout/ so a system run (which never has _heldout/) can still import this
    module for run_probe without pulling in the answer key."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return run_probe(mod.candidate(), version=version)


def mechanism_scope(candidate) -> bool:
    """True iff the candidate is a leading-dash submodule value handed to a child
    process (same argument-injection sink family as CVE-2017-1000117), not an
    unrelated bug. The dash may be in the url value or in the ssh host."""
    url = candidate.get("url", "") if isinstance(candidate, dict) else str(candidate)
    return url.startswith("-") or "://-" in url


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)   # differential precondition: seed blocked on v1
    return o


# --------------------------------------------------------------------------- #
# Build / teardown of the three from-source git images.
# --------------------------------------------------------------------------- #
def _have_image(img: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", img],
                          capture_output=True).returncode == 0


def build_images(force=False):
    for v, img in IMAGE.items():
        if force or not _have_image(img):
            r = subprocess.run(
                ["docker", "build", "--build-arg", f"GIT_VER={GIT_VER[v]}",
                 "-t", img, str(HERE)],
                text=True, capture_output=True, check=False,
            )
            if r.returncode != 0:
                raise RuntimeError(f"build {img} failed:\n{r.stderr[-2000:]}")


def teardown_images():
    for img in IMAGE.values():
        subprocess.run(["docker", "rmi", "-f", img], capture_output=True)


# --------------------------------------------------------------------------- #
# Gate.
# --------------------------------------------------------------------------- #
def gate() -> dict:
    return validate_case(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
    )


def run_gate(keep=False) -> dict:
    global FLAG
    FLAG = new_flag()
    build_images()
    result = gate()
    # optional negatives (not part of validate_case, recorded for the log)
    result["_residual_blocked_on_v2"] = "PCB_HIT" not in bypass_poc(version="v2")["output"]
    result["_original_blocked_on_v2"] = "PCB_HIT" not in original_poc(version="v2")["output"]
    result["_flag"] = FLAG
    if not keep:
        teardown_images()
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true", help="gate against already-built images (needs PCB_FLAG)")
    ap.add_argument("--run-gate", action="store_true", help="build images + gate + teardown")
    ap.add_argument("--keep", action="store_true", help="keep images after --run-gate")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep=a.keep), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
