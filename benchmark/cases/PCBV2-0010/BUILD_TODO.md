# BUILD_TODO — traefik-cve-2026-29054

Pair: CVE-2024-45410 -> CVE-2026-29054  (Traefik, Auth_Bypass)

- [ ] Resolve versions: V0 (vulnerable, pre-CVE-2024-45410 fix), V1 (=CVE-2024-45410-patched, target), V2 (=CVE-2026-29054-patched, optional).
- [ ] Build V1 Docker (flag-instrumented) + optional V0/V2. Set base urls in oracle.py.
- [ ] Plant FLAG at the DEFENDED resource (see case.json .flag). Must not perturb the vuln.
- [ ] Write original_poc (CVE1 seed): triggers+reaches flag on V0, BLOCKED on V1.
- [ ] Write _heldout/bypass_poc (CVE2 residual): reaches flag on V1.
- [ ] Run gate(): all three checks True -> set case.json status.stage = gate_passed.
- [ ] NEVER expose _heldout/* to the system-under-test.
