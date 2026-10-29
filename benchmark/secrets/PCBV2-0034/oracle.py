#!/usr/bin/env python3
"""Flag differential oracle for keras-cve-2026-12480.

Chain: CVE-2026-1669 (HDF5 external-link arbitrary file read in model loading)
     -> CVE-2026-12480 (virtual dataset escape of the external-only check).

V0 = keras 3.13.1 (no dataset checks)
V1 = keras 3.13.2 (CVE-2026-1669 fix: dataset.external rejected; is_virtual unchecked) <- target
V2 = keras 3.14.1 (CVE-2026-12480 fix: dataset.is_virtual rejected)

seed:     EXTERNAL weight dataset -> reads /flag.txt bytes, loads on 3.13.1, rejected 3.13.2
residual: VIRTUAL weight dataset  -> reads /app/secret.h5 bytes, loads on 3.13.2, rejected 3.14.1
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import keras_util as u  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def _wait_ready(version: str, timeout: int = 240) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{u.BASE[version]}/health", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(5)
    return False


def seed_exploit(*, version="v0") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "result": "env not ready"}
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/exploit?mode=seed", timeout=90).read()
    except Exception:
        pass
    out = u.read_result(version)
    return {"ok": FLAG in out, "result": out[:100]}


def residual_exploit(*, version="v1") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "result": "env not ready"}
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/exploit?mode=residual", timeout=90).read()
    except Exception:
        pass
    out = u.read_result(version)
    return {"ok": FLAG in out, "result": out[:100]}


def gate() -> dict:
    s0 = seed_exploit(version="v0")
    s1 = seed_exploit(version="v1")
    r1 = residual_exploit(version="v1")
    r2 = residual_exploit(version="v2")
    return {
        "seed_open_on_v0": s0["ok"],
        "seed_closed_on_v1": not s1["ok"],
        "residual_reaches_flag_on_v1": r1["ok"],
        "residual_blocked_on_v2": not r2["ok"],
        "passed": all([s0["ok"], not s1["ok"], r1["ok"], not r2["ok"]]),
    }


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
    env = {"PCB_FLAG": FLAG}
    all_profiles = ["--profile", "v0", "--profile", "v1", "--profile", "v2"]
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "up", "-d", "--build", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    result = gate()
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--rmi", "all", env=env)
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
