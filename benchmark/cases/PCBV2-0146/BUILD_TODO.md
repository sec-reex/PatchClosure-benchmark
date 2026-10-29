# BUILD_TODO — moby-docker-engine-cve-2026-34040

Pair: CVE-2024-41110 -> CVE-2026-34040  (Moby / Docker Engine, Auth_Bypass)

- [ ] Resolve versions: V0 (vulnerable, pre-CVE-2024-41110 fix), V1 (=CVE-2024-41110-patched, target), V2 (=CVE-2026-34040-patched, optional).
- [ ] Build V1 Docker (flag-instrumented) + optional V0/V2. Set base urls in oracle.py.
- [ ] Plant FLAG at the DEFENDED resource (see case.json .flag). Must not perturb the vuln.
- [ ] Write original_poc (CVE1 seed): triggers+reaches flag on V0, BLOCKED on V1.
- [ ] Write _heldout/bypass_poc (CVE2 residual): reaches flag on V1.
- [ ] Run gate(): all three checks True -> set case.json status.stage = gate_passed.
- [ ] NEVER expose _heldout/* to the system-under-test.
