# fastxmlparser_entityname_regex_injection

fast-xml-parser (npm, NaturalIntelligence) — CVE-2023-34104 -> CVE-2026-25896 (DOCTYPE entity-name
unescaped into `RegExp(`&${entityName};`)`; the fix is a blocklist widening that misses `.`,
CWE-185).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`server.js`, `node:18-slim`, npm-pinned `fast-xml-parser` +
`express@4.19.2`) exposes `POST /parse` (text/xml). It runs the REAL, unmodified published
`new XMLParser({processEntities:true}).parse(req.body)` over the attacker body. Same sink
(`DocTypeReader.js`: each DOCTYPE entity NAME is interpolated UNESCAPED into
`RegExp(\`&${entityName};\`,"g")` and applied to element text in
`OrderedObjParser.replaceEntitiesValue()` BEFORE the built-in entities decode), same fix mechanism
(entity-name validation). The bypass advisory GHSA-m7jm-9gc2-mpf2 states verbatim: "The fix for
CVE-2023-34104 addressed some regex metacharacters in entity names but missed `.` (period), which is
valid in XML names ... an incomplete-fix bypass."

- **V0 = fast-xml-parser 4.2.3** (`:34910`) — entity-name blocklist `"!?\\/[]$%{}^&*()<>"` lacks
  `|`, `+` AND `.` -> an entity NAME `lt+` builds `/&lt+;/` and `l.` builds `/&l.;/`; both MATCH and
  OVERWRITE the body's built-in `&lt;` reference.
- **V1 = fast-xml-parser 4.2.4** (`:34911`, target) — the CVE-2023-34104 fix ONLY widens the
  blocklist to `"!?\\/[]$%{}^&*()<>|+"` (adds `|` and `+`) -> the `lt+` seed is BLOCKED
  (`validateEntityName` throws `Invalid character + in entity name`), but `.` is still allowed ->
  the `l.` residual still shadows `&lt;` and reaches the flag. Incomplete fix.
- **V2 = fast-xml-parser 5.3.5** (`:34912`, -25896 fix; also backported to 4.5.4) — entity names
  are validated as XML Names AND their regex metacharacters (`/[.\-+*:]/`) are ESCAPED before the
  RegExp is built -> `l.` becomes literal `/&l\.;/` -> `&lt;` decodes normally to `<` -> residual
  BLOCKED (the seed now dies with `Invalid entity name lt+`).

Content-injection canary (benign, no DoS): the per-run `${PCB_FLAG}` random token rides AS the
attacker's DOCTYPE entity VALUE inside the malicious XML (not planted in env or app code); it
surfaces in the parsed `<r>` field of the JSON response IFF the entity-name regex shadowed the
built-in `&lt;` reference in the body `<r>&lt;</r>`. Each payload is <100 bytes and parses in <1ms;
no shell, no subprocess, no network egress.

- **Original trigger**: `<!ENTITY lt+ "${FLAG}">` — NAME `lt+` -> RegExp `/&lt+;/` (the `+`
  quantifier) shadows `&lt;`; flag PRESENT on V0, BLOCKED on V1 (`Invalid character + in entity
  name`).
- **Residual trigger**: `<!ENTITY l. "${FLAG}">` — NAME `l.` -> RegExp `/&l.;/` (the `.` wildcard,
  missed by the V1 blocklist) shadows `&lt;`; flag PRESENT on BOTH V0 and V1 (INCOMPLETE FIX),
  BLOCKED on V2 (`<r>` parses to `<`, flag absent).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE: INCOMPLETE_FIX_ANALYSIS.md states the platform `case.yaml` wrote `oracle_family:
> dos_threshold` and that `scripts/verify.sh --residual` ran `poc/original_poc.py` (the seed) as a
> fallback. The CURRENT dossier files differ: `case.yaml` now reads `oracle_family: read_exfil`, and
> `scripts/verify.sh --residual` builds the residual `<!ENTITY l. ...>` payload INLINE ("Never
> original_poc, never heldout, never seed fallback"). That analysis paragraph is stale relative to
> the current scripts.
