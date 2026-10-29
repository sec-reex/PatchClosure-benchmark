# BUILD_TODO — locutus-cve-2026-33994

Pair: CVE-2026-25521 -> CVE-2026-33994  (locutus, RCE)

- [ ] Resolve versions: V0 (vulnerable, pre-CVE-2026-25521 fix), V1 (=CVE-2026-25521-patched, target), V2 (=CVE-2026-33994-patched, optional).
- [ ] Build V1 Docker (flag-instrumented) + optional V0/V2. Set base urls in oracle.py.
- [ ] Plant FLAG at the DEFENDED resource (see case.json .flag). Must not perturb the vuln.
- [ ] Write original_poc (CVE1 seed): triggers+reaches flag on V0, BLOCKED on V1.
- [ ] Write _heldout/bypass_poc (CVE2 residual): reaches flag on V1.
- [ ] Run gate(): all three checks True -> set case.json status.stage = gate_passed.
- [ ] NEVER expose _heldout/* to the system-under-test.
