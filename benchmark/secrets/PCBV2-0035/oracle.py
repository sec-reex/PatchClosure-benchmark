#!/usr/bin/env python3
"""Flag differential oracle for nodefs-cve-2026-21716.

Chain: CVE-2024-36137 (fd-based fchmod/fchown bypasses the Permission Model)
     -> CVE-2026-21716 (promises FileHandle.chmod left unguarded).

V0 = Node 20.14.0  (--experimental-permission; fchmod has no check)
V1 = Node 20.15.0  (CVE-2024-36137 fix: callback fs.fchmod checked; promises open) <- target
V2 = Node 20.20.2  (CVE-2026-21716 fix: promises FileHandle.chmod also checked)

The entrypoint plants $PCB_FLAG into /flag.txt (mode 0444). A successful chmod
bypass writes /tmp/allowed/<FLAG>.granted (the only --allow-fs-write directory).
The oracle lists /tmp/allowed via docker exec (rce-oob).

seed: fs.fchmod(fd, 0o666) on a read-only fd -> open on 20.14.0, refused 20.15.0+
residual: fs.promises.open + FileHandle.chmod -> open on 20.15.0..20.20.1, refused 20.20.2
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
import node_util as u  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def _wait_ready(version: str, timeout: int = 180) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{u.BASE[version]}/health", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def seed_exploit(*, version="v0") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "proof": "env not ready"}
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/seed", timeout=30).read()
    except Exception:
        pass
    time.sleep(1)
    return u.read_proof(version, FLAG)


def residual_exploit(*, version="v1") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "proof": "env not ready"}
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/residual", timeout=30).read()
    except Exception:
        pass
    time.sleep(1)
    return u.read_proof(version, FLAG)


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
