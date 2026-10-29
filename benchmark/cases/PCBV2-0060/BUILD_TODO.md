# BUILD_TODO — hl7-fhir-org-hl7-fhir-core-cve-2023-28465  (DONE: gate_passed)

Pair: CVE-2023-24057 -> CVE-2023-28465  (HL7 FHIR (org.hl7.fhir.core), Zip-Slip / partial path traversal (CWE-22))

- [x] Resolve versions: V0=5.6.90 (vulnerable), V1=5.6.92 (CVE-2023-24057-patched, target), V2=5.6.106 (CVE-2023-28465-patched).
- [x] Recipe env: Dockerfile pulls published Maven artifact org.hl7.fhir.r4b:<ver> + deps, compiles Driver.java that calls the REAL TerminologyCacheManager.unzip sink. Profiles v0/v1/v2.
- [x] Canary (state-write/zip-slip): crafted archive writes a $PCB_FLAG-content file OUTSIDE the extraction root; oracle checks the escape. Data-only, no app-code edits.
- [x] original_poc (CVE1 seed): mid-'..' archive -> ESCAPES on V0, BLOCKED on V1.
- [x] _heldout/bypass_poc (CVE2 residual): sibling partial-path archive -> ESCAPES on V1, BLOCKED on V2.
- [x] Gate (Variant A) all three True -> status.stage = gate_passed. See repro.log.
- [x] Teardown: down -v --rmi all; disk freed; case dir ~68K (recipe-only).
