# BUILD_TODO — awstats-cve-2020-29600  [GATE PASSED]

Pair: CVE-2017-1000501 -> CVE-2020-29600  (AWStats, CWE-22 path traversal via config=)

- [x] Resolve versions: V0=7.6 (vulnerable), V1=7.7 (1000501-patched via `s/\.\.//g`, target),
      V2=7.8 (29600-patched: rel2abs absolute-path fallback commented out).
- [x] Recipe env (no committed images/source): parametrised Dockerfile git-clones eldy/awstats at
      pinned tag (ARG AWSTATS_REF) on debian:bookworm-slim + apache2 + perl (mod_cgid). Profiles v0/v1/v2.
- [x] Plant FLAG at the DEFENDED resource: /pcb_canary/flag.conf (outside docroot & all config search
      dirs), written by the compose entrypoint from $PCB_FLAG as `Include "<FLAG>"`. No app code touched.
- [x] original_poc.py (CVE1 seed, `..` traversal `config=/etc/../pcb_canary/flag.conf`): HIT on V0, BLOCKED on V1.
- [x] _heldout/bypass_poc.py (CVE2 residual, absolute `config=/pcb_canary/flag.conf`): HIT on V1, CLOSED on V2.
- [x] Gate via `python3 oracle.py --run-gate`: all three checks True -> case.json status.stage = gate_passed.
- [x] repro.log + _heldout/flag_spec.json + _heldout/evidence.json + case.json fully populated.
- [x] NEVER expose _heldout/* to the system-under-test.

## Run the gate again
```
cd benchmark/cases/awstats-cve-2020-29600
python3 oracle.py --run-gate          # build -> up(v0,v1) -> gate -> down; prints 3 booleans + passed
```
Teardown of images: `PCB_FLAG=teardown docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`
