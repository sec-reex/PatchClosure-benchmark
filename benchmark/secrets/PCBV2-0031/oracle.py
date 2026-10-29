#!/usr/bin/env python3
"""Flag differential oracle for astro-cve-2026-59729.

Chain: CVE-2026-54298 (unescaped spread attribute names in SSR, addAttribute)
     -> CVE-2026-59729 (renderHTMLElement inline attribute loop missed the fix).

V0 = astro 6.4.5  (no attribute-name guard)
V1 = astro 7.0.4  (CVE-2026-54298 fix: addAttribute guarded; renderHTMLElement open) <- target
V2 = astro 7.0.6  (CVE-2026-59729 fix: renderHTMLElement also guarded)

The server embeds the flag (from /flag.txt) in an injected attribute name and
renders it through the real SSR functions; the response echoes the flag when the
attribute name is emitted unescaped.

seed:     addAttribute('v', 'x" data-pcb="<FLAG>')       -> open 6.4.5, dropped 7.0.4
residual: renderHTMLElement(<HTMLElement>, {[key]: 'v'}) -> open 7.0.4, dropped 7.0.6
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
import astro_util as u  # noqa: E402

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
        return {"ok": False, "flag": "env not ready"}
    r = u.exploit(version, "seed")
    return {"ok": r.get("flag") == FLAG, "flag": r.get("flag", "")}


def residual_exploit(*, version="v1") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "flag": "env not ready"}
    r = u.exploit(version, "residual")
    return {"ok": r.get("flag") == FLAG, "flag": r.get("flag", "")}


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
