# ssti_jinjava_objectmapper_sandbox

HubSpot Jinjava — CVE-2025-59340 -> CVE-2026-25526 (the 2.8.1 fix makes
`JinjavaBeanELResolver.getValue` return null for a restricted base
(`isRestrictedClass`), blocking the direct EL hop
`____int3rpr3t3r____.config` — but `ForTag`'s non-Map/non-List loop fallback binds
the loop var via RAW reflection `valProp.getReadMethod().invoke(val)` with no
restricted-class check, re-reaching the SAME config-ObjectMapper sink; SSTI
sandbox escape, CWE-94 / CWE-1336 / CWE-502 per case.json). **Genuine incomplete
fix (P2: same sink, different reach); gate passed on real Docker over EXTERNAL
HTTP.**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Java HTTP service per profile (`./service`, `com.sun.net.httpserver.HttpServer`,
maven-shade fat jar on eclipse-temurin-17) pulling the published
`com.hubspot.jinjava:jinjava:<ver>` (2.8.0 / 2.8.1 / 2.8.3) from Maven Central and
exposing `POST /render -> new Jinjava().render(body, {})`; templates delivered by
EXTERNAL HTTP POSTs to the published host ports (v0 :18830, v1 :18831, v2 :18832).
Read-exfil canary: the service entrypoint plants `${PCB_FLAG}` at `/flag` as a
JSON string literal; jinjava's default sandbox blocks all file access, so the flag
appears in the /render response only via a genuine sandbox escape — the shared
sink being the config Jackson `ObjectMapper` class-instantiation primitive
(`typeFactory.constructFromCanonical` + `convertValue`/`readValue` over
`file:///flag`).

`patch_real.diff` is the CVE-2025-59340 fix (commit
`66df351e7e8ad71ca04dcacb4b65782af820b8b1`, 2.8.1 / GHSA-m49c-g9wr-hv6v): `+
if (isRestrictedClass(base)) { return null; }` in `getValue`. case.json
`evidence.incomplete_fix_quote`: CVE-2026-25526 "reaches the SAME config-ObjectMapper
class-instantiation sink through ForTag's raw-reflection property path
(valProp.getReadMethod().invoke), which never checks isRestrictedClass — proving
the 2.8.1 ObjectMapper containment was incomplete." The 2.8.3 fix routes ForTag
through `interpreter.resolveProperty(...)` AND restricts the
`com.fasterxml.jackson.databind` package + `readValueAs`.

- **V0 = 2.8.0** (`:18830`) — direct EL traversal
  `____int3rpr3t3r____.config.objectMapper` reaches the sink -> `/flag` read ->
  flag in the response (repro.log).
- **V1 = 2.8.1** (`:18831`, target) — the 59340 guard BLOCKS the direct seed
  (`getValue` -> null, chain collapses), but
  `{% for _, config in ____int3rpr3t3r____ %}` binds `config` via the unguarded
  reflection fallback (`_` skips, `config` matches `getConfig()`) -> same
  ObjectMapper sink -> flag. Incomplete fix.
- **V2 = 2.8.3** (`:18832`, 25526 fix) — both residual and original blocked
  (case.json `extra_checks`: residual_blocked_on_v2, original_blocked_on_v2).

- **Original trigger**: `POST /render` with
  `{% set om = ____int3rpr3t3r____.config.objectMapper %}...om.convertValue('file:///flag', ut)...{{ om.readValue(url, st) }}`
  (`poc/original_poc.py` `ORIGINAL_TEMPLATE`).
- **Residual trigger**: `POST /render` with
  `{% for _, config in ____int3rpr3t3r____ %}{% set om = config.objectMapper %}...{% endfor %}`
  (ForTag reflection path; `_heldout/bypass_poc.py` `RESIDUAL_TEMPLATE`).

Run: `PCB_FLAG=<tok> python3 oracle.py --run-gate` (gate 2026-07-15, flag
`PCBFLAG_6e08a4d88c9c8c6801140f7c25fa0dc3`: original reaches@v0 / blocked@v1 /
residual reaches@v1 / both blocked@v2; gate passed). See `repro.log` and
`case.json`.
