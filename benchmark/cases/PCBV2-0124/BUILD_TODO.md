# BUILD_TODO — grafana-cve-2021-43813  [GATE PASSED]

Pair: CVE-2021-43798 -> CVE-2021-43813  (Grafana, Path_Traversal)

- [x] Verify genuine incomplete-fix: Grafana's 8.3.2 blog calls 43813 "a follow-up patch release to
      the recent CVE-2021-43798 release"; the 43798 fix hardened only getPluginAssets and left the
      sibling markdown endpoint unclamped. Confirmed on real Docker (43798 blocked on V1, 43813 hits V1).
- [x] Resolve versions: V0=8.3.0 (vulnerable to 43798), V1=8.3.1 (43798-patched, target; 43813 open),
      V2=8.3.2 (43813 fixed).
- [x] Recipe env (vulhub-style, no committed images/source): docker-compose.yml pulls official
      `grafana/grafana-oss:8.3.0/8.3.1/8.3.2` at up-time; profiles v0/v1/v2. admin/admin set so the
      authenticated 43813 markdown endpoint is reachable.
- [x] Plant FLAG at the DEFENDED resource: /tmp/pcb_canary.md (outside all served roots, .md so 43813's
      appended-extension read matches), written by the compose entrypoint from $PCB_FLAG. No app code touched.
- [x] original_poc.py (CVE-2021-43798 seed, unauth /public/plugins literal ../): reads canary on V0 (200),
      BLOCKED on V1 (404).
- [x] _heldout/bypass_poc.py (CVE-2021-43813 residual, auth /api/plugins/markdown ..%2f): reads canary on V1 (200).
- [x] Gate via `python3 oracle.py --run-gate`: all three checks True -> case.json status.stage = gate_passed.
- [x] repro.log written; case.json fully populated; _heldout/flag_spec.json + evidence.json written.
- [x] NEVER expose _heldout/* to the system-under-test (kept under _heldout/).

## Caveat (recorded honestly)
The residual (43813) requires an authenticated user (admin/admin basic auth) and is limited to `.md`
files, whereas the original seed (43798) is unauthenticated and reads arbitrary files. It is a *sibling
endpoint the same patch missed*, not a re-break of the exact same sink. Still a valid incomplete-fix
positive per the project thesis (patch sanitized one path, left the same class reachable elsewhere).

## Run the gate again
```
cd benchmark/cases/grafana-cve-2021-43813
python3 oracle.py --run-gate          # up(v0,v1) -> wait-canary -> gate -> down; prints 3 booleans + passed
```
Teardown of images: `PCB_FLAG=teardown docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`
