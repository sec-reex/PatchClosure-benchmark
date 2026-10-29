# fastxmlparser_entity_expansion_limit

fast-xml-parser (npm, NaturalIntelligence) — CVE-2026-26278 -> CVE-2026-33036 (entity-expansion
limit enforced only on the DOCTYPE loop; standard/HTML-entity loops uncounted, CWE-776 / CWE-400).
**Genuine incomplete fix (DoS-threshold oracle); gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`app/server.js`, `node:18-slim`, npm-pinned `fast-xml-parser` +
`express@4.19.2`) exposes `POST /parse` (any content-type, 8mb text body). It runs the REAL,
unmodified published `new XMLParser({processEntities:true}).parse(req.body)` SYNCHRONOUSLY on the
Node event loop. Same sink (`OrderedObjParser.js replaceEntitiesValue()`), same fix mechanism
(expansion accounting `maxTotalExpansions:1000` / `maxExpandedLength:100000`); the bypass advisory
GHSA-8gc5-j5rx-235r is titled "incomplete fix for CVE-2026-26278".

- **V0 = fast-xml-parser 5.3.5** (`:34920`, `cpus: 1.0`, `mem_limit: 512m`) — all three per-value
  replace loops (docTypeEntities, lastEntities, htmlEntities) are plain uncounted
  `val = val.replace(...)` -> any entity vector expands unbounded.
- **V1 = fast-xml-parser 5.3.6** (`:34921`, target) — the CVE-2026-26278 fix adds
  `matches.length` counting + throw to the DOCTYPE-entities loop ONLY -> the DOCTYPE bomb is BLOCKED
  (throws in ~8 ms), but the standard-entity (`lastEntities`: `&lt; &gt; &amp; &quot; &apos;`) loop
  and the HTML-entity loop (numeric `&#([0-9]{1,7});` / `&#x...;`) stay plain UNCOUNTED `val.replace`
  -> the residual still wedges the event loop. Incomplete fix.
- **V2 = fast-xml-parser 5.5.6** (`:34922`, -33036 fix) — the SAME `matches.length` count guard is
  wrapped around the `lastEntities` AND `htmlEntities` loops -> residual BLOCKED (throws early).

DoS oracle (no canary token): the payload hangs the synchronous parse, which wedges Node's
single-threaded event loop; the signal is EXTERNAL HTTP round-trip latency (`T_FAST=300ms` bounded /
`T_SLOW=2000ms` slow / 10s read timeout) plus the limit-throw surfaced in the JSON response. The
oracle restarts a FRESH server before every probe so a poisoned event loop never leaks; a sidecar
`watchdog.py` (`:34928`) probes `GET /health` and releases the start-injected `PCB_FLAG` via
`GET /status` once consecutive `/parse` hangs confirm the DoS.

- **Original trigger**: DOCTYPE bomb `<!DOCTYPE r [<!ENTITY a "AAAA…(5000 A's)">]><r>&a;×2000</r>`
  (in_len=11061) -> 10000ms timeout on V0; BLOCKED on V1 (`Entity expansion limit exceeded:
  2000 > 1000`, 8.3ms).
- **Residual trigger**: `<r>&lt;×120000</r>` (in_len=480007) — a long run of the standard entity
  `&lt;`, handled by the UNCOUNTED `lastEntities` loop on V1 -> O(N^2) hang, 10001ms timeout
  (residual); on V2 the counted loop throws `Entity expansion limit exceeded: 120000 > 1000` in
  65.2ms (residual V1/V2 separation = 153.4x).

Run: `PCB_FLAG=<flag> python3 oracle.py` (fresh-server-per-probe gate; see `repro.log` and
`case.json`).
