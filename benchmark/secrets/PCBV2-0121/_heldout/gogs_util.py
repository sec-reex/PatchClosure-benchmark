"""gogs-cve-2025-64111 shared config/detect helpers (restored 2026-08-02: file was
missing from _heldout; logic mirrors the gate described in repro.log)."""

ADMIN_USER = "pcbadmin"
ADMIN_PASS = "admin123"
REPO_NAME = "pcb-repo"
PORTS = {"v0": 23400, "v1": 23401, "v2": 23402}
CONTAINERS = {"v0": "pcb-gogs-v0", "v1": "pcb-gogs-v1", "v2": "pcb-gogs-v2"}


def base_url(version: str = "v1") -> str:
    return f"http://127.0.0.1:{PORTS[version]}"


def malicious_config() -> str:
    return "[core]\nfsmonitor = /data/pcb/fsmon.sh\n"


def clear_flag_result(version: str = "v1") -> None:
    import subprocess
    subprocess.run(
        ["docker", "exec", CONTAINERS[version], "sh", "-c", "rm -f /tmp/pcb_result.txt"],
        capture_output=True, timeout=15)


def read_flag_result(version: str = "v1") -> str:
    import subprocess
    r = subprocess.run(
        ["docker", "exec", CONTAINERS[version], "sh", "-c", "cat /tmp/pcb_result.txt 2>/dev/null"],
        capture_output=True, text=True, timeout=15)
    return r.stdout.strip()
