# ruby-rexml-cve-2014-8090

Ruby REXML (MRI stdlib) — CVE-2014-8080 → CVE-2014-8090 (entity-expansion DoS: per-value byte cap
added while the COUNT limit was unreachable during DTD parse, CWE-776).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (`gate_result.json`:
residual V1 timeout at 10001.3ms vs V2 "limited" in 66.1ms; original V0 timeout 10001.4ms vs V1
"limited" in 16.4ms; benign ~14ms everywhere; `"passed": true`).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Ruby web app: stdlib WEBrick (`app/server.rb`, bind-mounted; REXML is the exact library
bundled in the official `ruby:2.1.x` image — no vendored/lifted source) exposes
`POST /parse` (raw XML) -> `REXML::Document.new(body)` + `each_recursive` full text consumption,
synchronously in the request handler. Stock 2014 REXML defaults kept
(`entity_expansion_limit=10000`, `entity_expansion_text_limit=10240`). Same sink family on all
versions; the advisory calls CVE-2014-8090 "an additional fix for CVE-2014-8080" whose predecessor
"limited the size of a single entity expansion but did not limit the total number of entity
expansions".

- **V0 = ruby 2.1.3** (`:28220`) — bundled REXML has NO byte cap in `Entity#value` and NO
  `Document#document` -> original nested-parameter-entity byte bomb hangs the server
  (10001.4ms timeout).
- **V1 = ruby 2.1.4** (`:28221`, target) — CVE-2014-8080 fix adds the per-value byte cap in
  `Entity#value` (`raise "entity expansion has grown too large"`, entity.rb:145) -> the byte bomb
  is BLOCKED (16.4ms, "limited"), but the cap is a fresh local `sum` per call and
  `Document#document` is still absent -> during internal-DTD-subset parse
  `record_entity_expansion` is skipped (`unless document.nil?`), so the EMPTY-entity count bomb
  still hangs (10001.3ms timeout). Incomplete fix: bounds SIZE at one level, not the NUMBER of
  expansions.
- **V2 = ruby 2.1.5** (`:28222`, -8090 fix) — `Document#document => self` (document.rb:281), so
  `record_entity_expansion` runs during DTD parse and the 10000 COUNT limit fires
  (`"number of entity expansions exceeded, processing aborted."`, document.rb:277) -> residual
  "limited" in 66.1ms.

Benign channel: none by design (`dos-threshold`) — signal is server-side latency of the EXTERNAL
`POST /parse` under a 10s client read timeout (DoS iff hang/crash or > T_SLOW 2000ms; bounded iff
< T_FAST 500ms); benign control XML (`payloads/benign.xml`) parses in ~14ms on all versions.
Fresh server per probe (kill + up); each container cpus=1.0 / mem_limit 1200m. No canary token, no
command execution.

- **Original trigger**: `payloads/original_attack.xml` — nested PARAMETER entities `%a;`..`%j;`
  (10x per level) + `<root>&bomb;</root>`; each `Entity#value` expansion on V0 is uncapped ->
  exponential text.
- **Residual trigger**: `payloads/residual_attack.xml` — EMPTY nested parameter entities
  `%a0;`..`%a30;` (2x per level) with `%trigger;` referenced INSIDE the internal DTD subset: every
  expansion yields "" so the byte cap never trips, but expansions = 2^30 while
  `Document#document == nil` on V0/V1 keeps the count limit uninvoked. Same shape as the official
  workaround target (`Document#document; self; end`).

Run: `python3 oracle.py --run-gate --with-v2` (compose bases loaded via
`skopeo copy docker://ruby:<ver> docker-daemon:ruby:<ver>-official`, legacy builder
`DOCKER_BUILDKIT=0` — the 2016-era schema-v1 manifests). See `repro.log`, `gate_result.json` and
`case.json`.
