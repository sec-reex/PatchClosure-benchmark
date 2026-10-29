"""Shared plumbing for nodefs-cve-2026-21716 (rce-oob via docker exec)."""

import subprocess

CONTAINERS = {"v0": "pcb-nodefs-v0", "v1": "pcb-nodefs-v1", "v2": "pcb-nodefs-v2"}
BASE = {"v0": "http://127.0.0.1:33770", "v1": "http://127.0.0.1:33771", "v2": "http://127.0.0.1:33772"}


def read_proof(version: str, flag=None):
    """List /tmp/allowed in the container; return the granted proof filename(s)."""
    r = subprocess.run(
        ["docker", "exec", CONTAINERS[version], "sh", "-c", "ls /tmp/allowed/ 2>/dev/null"],
        capture_output=True, text=True, timeout=30,
    )
    out = r.stdout.strip()
    if flag:
        return {"ok": f"{flag}.granted" in out, "proof": out[:200]}
    return {"ok": bool(out), "proof": out[:200]}
