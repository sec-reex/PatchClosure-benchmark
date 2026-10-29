"""Shared plumbing for keras-cve-2026-12480 (rce-oob via docker exec)."""

import subprocess

CONTAINERS = {"v0": "pcb-keras-v0", "v1": "pcb-keras-v1", "v2": "pcb-keras-v2"}
BASE = {"v0": "http://127.0.0.1:33880", "v1": "http://127.0.0.1:33881", "v2": "http://127.0.0.1:33882"}


def read_result(version: str) -> str:
    r = subprocess.run(
        ["docker", "exec", CONTAINERS[version], "cat", "/tmp/pcb_result.txt"],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip() if r.returncode == 0 else ""
