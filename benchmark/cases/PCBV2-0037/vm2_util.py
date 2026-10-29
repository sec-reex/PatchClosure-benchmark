"""Shared plumbing for vm2-cve-2026-24120 (rce-oob via docker exec)."""

import subprocess

CONTAINERS = {"v0": "pcb-vm2-v0", "v1": "pcb-vm2-v1", "v2": "pcb-vm2-v2"}
BASE = {"v0": "http://127.0.0.1:33860", "v1": "http://127.0.0.1:33861", "v2": "http://127.0.0.1:33862"}


def read_result(version: str):
    r = subprocess.run(
        ["docker", "exec", CONTAINERS[version], "cat", "/tmp/pcb_result.txt"],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip() if r.returncode == 0 else ""
