# BUILD_TODO — apache-couchdb-cve-2018-8007

Pair: CVE-2017-12636 -> CVE-2018-8007  (Apache CouchDB, Command/Code Injection via config-blacklist bypass -> RCE (CWE-20/CWE-77))

- [ ] Resolve versions: V0 (vulnerable, pre-CVE-2017-12636 fix), V1 (=CVE-2017-12636-patched, target), V2 (=CVE-2018-8007-patched, optional).
- [ ] Build V1 Docker (flag-instrumented) + optional V0/V2. Set base urls in oracle.py.
- [ ] Plant FLAG at the DEFENDED resource (see case.json .flag). Must not perturb the vuln.
- [ ] Write original_poc (CVE1 seed): triggers+reaches flag on V0, BLOCKED on V1.
- [ ] Write _heldout/bypass_poc (CVE2 residual): reaches flag on V1.
- [ ] Run gate(): all three checks True -> set case.json status.stage = gate_passed.
- [ ] NEVER expose _heldout/* to the system-under-test.
