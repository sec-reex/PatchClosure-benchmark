# hapi-fhir-org-hl7-fhir-core-cve-2026-55470

HAPI FHIR / `org.hl7.fhir.core` DSTU2 `FHIRPathEngine` ReDoS (CWE-1333).
Incomplete-fix pair: **CVE-2026-45367** (V1) -> **CVE-2026-55470** (V2). `class_kind = dos-threshold`,
`run_mode = real-app-http` (external HTTP trigger).

## Mechanism (guard-consistency incomplete fix)
FHIRPath `matches(regex)` / `replaceMatches(regex,repl)` hand an attacker-supplied regex straight to
`java.util.regex`. CVE-2026-45367 wrapped these in a 500ms `RegexTimeout` guard, but in the DSTU2
module it patched **replaceMatches()** and **missed matches()** (still raw `String.matches`).
CVE-2026-55470 = the residual `matches()` ReDoS, closed at 6.9.10 (commit `56376f7...`).

- **original** `replaceMatches('(.*a){30}','x')` — closed at V1 (RegexTimeout guard)
- **residual** `matches('(.*a){30}')` — V1 left it unguarded in DSTU2; closed only at V2
- same class / same evil regex `(.*a){30}` / same module -> sibling FHIRPath regex functions.

## Real app + external HTTP trigger
A tiny **REAL Java HTTP service** (`com.sun.net.httpserver.HttpServer`, `harness/src/main/java/Server.java`)
is built per profile against the **REAL published** `ca.uhn.hapi.fhir:org.hl7.fhir.dstu2` (pulled from
Maven Central at 6.9.6 / 6.9.7 / 6.9.10). `POST /eval {expr, input}` builds a DSTU2 `FHIRPathEngine`
and evaluates the user FHIRPath expression against `StringType(input)` — the library's own
`funcMatches` / `funcReplaceMatches` reach `java.util.regex`. This mirrors a real FHIR server
evaluating untrusted FHIRPath (search params, validation invariants). The evaluation runs
**synchronously** inside the HTTP handler thread, so a catastrophic regex **hangs the response**;
the oracle triggers it from **outside** the container and measures server-side latency.

## Versions (Maven `ca.uhn.hapi.fhir:org.hl7.fhir.dstu2`)
| profile | version | port | state |
|---|---|---|---|
| v0 | 6.9.6 | 26906 | vulnerable (raw matches + raw replaceAll) |
| v1 | 6.9.7 | 26907 | TARGET — replaceMatches guarded, **matches still raw** |
| v2 | 6.9.10 | 26910 | matches guarded (CVE-2026-55470 fix) |

## Gate (real Docker, maven:3.9-eclipse-temurin-17, external HTTP)
SERVER-SIDE latency of `POST /eval` (ms). Guard bounds a call to ~500ms (RegexTimeout ->
PathEngineException); an unguarded call backtracks catastrophically and hangs to the 10s HTTP read
timeout. Thresholds: `T_FAST=2000ms` (bounded/benign), `T_SLOW=5000ms` (catastrophic).

| probe | v0 | v1 | v2 |
|---|---|---|---|
| original `replaceMatches` | ~10000 (HANG) | ~511 (BLOCKED) | ~510 |
| residual `matches` | ~10000 (HANG) | **~10000 (HANG)** | ~510 (CLOSED) |
| benign `matches('a+')` | ~8 | ~8 | ~8 |

## Reproduce
```
python3 oracle.py        # builds v0/v1/v2, POSTs external probes, writes gate_result.json
```
Fresh server per probe (a wedged CPU-bound handler thread never poisons the next). NOTE: modern
`java.util.regex` prunes classic `(a+)+$` (0ms) — `(.*a){N}` is used because it survives the
optimizer (super-polynomial in N). See `repro.log`, `patch.diff`, `gate_result.json`.
