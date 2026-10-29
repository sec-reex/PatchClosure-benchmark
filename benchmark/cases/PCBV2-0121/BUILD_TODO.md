# BUILD_TODO -- gogs-cve-2025-64111

Pair: CVE-2024-56731 -> CVE-2025-64111  (Gogs, file write through symlink -> RCE)

- [x] Resolve versions: V0=0.13.2, V1=0.13.3, V2=0.13.4
- [x] Build Docker (flag-instrumented) with docker-compose profiles v0/v1/v2.
- [x] Plant FLAG at /data/pcb/flag.txt; fsmonitor script at /data/pcb/fsmon.sh.
- [x] Write original_poc (CVE1 seed): upload through symlink, reaches flag on V0, BLOCKED on V1.
- [x] Write _heldout/bypass_poc (CVE2 residual): API PUT through symlink, reaches flag on V1.
- [x] Run gate(): all three checks True. case.json status.stage = gate_passed.
- [x] Teardown: images removed, case dir text-only.
