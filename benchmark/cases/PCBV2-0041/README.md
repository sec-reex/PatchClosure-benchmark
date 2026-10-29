# deser_fastjson_autotype

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Alibaba fastjson (Java) — CVE-2017-18349 → CVE-2025-70974 (Deserialization / autoType, CWE-502). Genuine incomplete fix.

**Run mode: real-app-http.** A REAL small Java HTTP service (`com.pcb.DeserHttpService`, JDK
`com.sun.net.httpserver.HttpServer`) boots with the REAL, unmodified published fastjson on its
classpath and exposes `POST /deser` (application/json): it deserializes the raw JSON request body
through fastjson's autoType sink, **triggered by an EXTERNAL HTTP request**. `GET /health` is the
readiness probe. Host ports: V0=18810, V1=18811, V2=18812.

**Mechanism.** fastjson's autoType lets untrusted JSON name the class to instantiate:
`{"@type":"<class>"}` makes `JSON.parse()` resolve and construct that class. CVE-2017-18349 (fixed in
1.2.25) added `ParserConfig.checkAutoType()` + a prefix **denylist**. The guard is *string-prefix*
based (default-allow beyond the denied prefixes), so it was INCOMPLETE: CVE-2025-70974
(GHSA-jm7w-5684-pvh8, fixed in 1.2.48) is explicitly *"an incomplete fix for CVE-2017-18349"* — the
**class-cache** trick resolves a denied class past the denylist.

**Versions (recipe-only — Maven Central at build time, no vendored jars):**
- V0 = `fastjson:1.2.24` — pre-CVE-2017-18349, NO `checkAutoType`.
- V1 = `fastjson:1.2.25` — CVE-2017-18349 fix (`checkAutoType` + denylist), TARGET, incomplete.
- V2 = `fastjson:1.2.48` — CVE-2025-70974 fix (MiscCodec `loadClass(..,false)` — no class caching).

**The residual (class-cache / `TypeUtils.mappings`).** On the autoType-off path, `checkAutoType`
consults `getClassFromMapping()`/`deserializers.findClass()` BEFORE its denylist loop, and `MiscCodec`'s
`java.lang.Class` deserializer caches the loaded class into `TypeUtils.mappings` via the 2-arg
`loadClass(strVal, cl)`. So a two-entry document POSTed as ONE body — first cache the class via
`{"@type":"java.lang.Class","val":"X"}`, then reference `{"@type":"X"}` — resolves the SAME denied class
past the denylist. 1.2.48 changes `MiscCodec` to `loadClass(strVal, cl, false)` (`cache=false`) so
`getClassFromMapping()` misses and the denylist rejects `X`. (The `L...;` descriptor bypass is NOT used —
it was closed at 1.2.42, so it is not a valid 1.2.25→1.2.48 differential.) The service parses with
default config (autoType OFF); with `Feature.SupportAutoType` the denylist loop would run first and
defeat the cache form — source-verified.

Each request parses exactly as `JSON.parse(String)` (`DefaultJSONParser.parse` → `handleResovleTask` →
`close`) but with a FRESH `new ParserConfig()` (same real `checkAutoType` + same denyList) plus eviction
of only the canary key from the static `TypeUtils.mappings`, so each external request is
hermetic/order-independent. fastjson itself is never modified.

**Benign canary (benign-shadow-class).** `com.mchange` is on fastjson's OWN built-in denylist at both
1.2.25 and 1.2.48, so the benign bean `com.mchange.PcbFlagBean` stands in for a "dangerous" denied class
(real c3p0 is NOT on the classpath → no collision; fastjson's own `checkAutoType` decides). Its no-arg
CONSTRUCTOR reads `${PCB_FLAG}` from `/canary/flag.txt` and stashes it in `CanaryHolder` — fired only when
`checkAutoType` PERMITS the name and fastjson instantiates; the service echoes `PCB_CANARY_FLAG=<token>`
in the HTTP response. No gadget chain, no JNDI, no command execution.

**Gate (Variant A) — verified on real Docker over external HTTP (`python3 oracle.py --run-gate --with-v2`):**
- original(literal `{"@type":"com.mchange.PcbFlagBean","probe":"x"}`)@V0 → REACHES; @V1 → BLOCKED (`autoType is not support`).
- residual(class-cache `{"a":{"@type":"java.lang.Class","val":"..PcbFlagBean"},"b":{"@type":"com.mchange.PcbFlagBean"}}`)@V1 → REACHES; @V2 → BLOCKED.
- literal@V2 → BLOCKED. `passed=true`, `_residual_blocked_on_v2=true`, `_original_blocked_on_v2=true`.

Active files: `service/`, `canary/`, `Dockerfile`, `docker-compose.yml`, `pom.xml`, `oracle.py`,
`original_poc.py`, `_heldout/bypass_poc.py`, `case.json`, `patch.diff`, `repro.log`.
STALE (superseded, NOT compiled/referenced): `src/Driver.java`, `src/com/mchange/PcbFlagBean.java`
(the old in-process stdin driver). `_heldout/` is never exposed to the SUT.
