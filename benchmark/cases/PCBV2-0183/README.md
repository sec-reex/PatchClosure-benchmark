# redos_adobe_css_tools

@adobe/css-tools — CVE-2023-26364 -> CVE-2023-48631 (ReDoS / catastrophic regex backtracking in
`parse()`'s at-rule and selector regexes; CWE-1333, dos-threshold oracle). **Genuine incomplete fix;
gate passed on real Docker** (`gate_result.json`: `"passed": true`; repro.log: "VERDICT: gate_passed ...
INCOMPLETE FIX confirmed: CVE-2023-26364 (4.3.1) closes the @import bomb but leaves the selector()
`|\(.*?\)` residual catastrophically backtrackable until 4.3.2 removes the branch").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`node:18-slim`; `npm i express@4 @adobe/css-tools@<CSS_TOOLS_VERSION>`,
no vendored/edited source; `app/server.js`) exposes `GET /health` and `POST /parse {css}` ->
`css.parse(req.body.css)` running SYNCHRONOUSLY on the Node event loop — the documented parser sink —
so a catastrophic input HANGS the HTTP response (server-side ReDoS observed as EXTERNAL round-trip
latency; the JSON response echoes `server_ms` proving the latency is genuine parse compute).
`express.json` limit raised to 4mb so the ~140 KB residual reaches the parser. Containers are
cpus=1.0, mem_limit=512m; because a running regex cannot be interrupted, the oracle measures every
payload against a FRESH server (kill + `up -d` between probes). A compose `watchdog` (:26367,
`watchdog.py`) probes a BENIGN stylesheet on the target and releases the per-run `${PCB_FLAG}` via
`/status` after consecutive probe timeouts; the oracle itself is the dos-threshold latency check:
ReDoS iff latency > T_SLOW (2000ms) or read-timeout (10s), bounded iff < T_FAST (300ms) — no canary
in the success path.

- **V0 = @adobe/css-tools 4.3.0** (`:26364`) — non-block at-rule regex
  `^@import\s*((:?[^;'"]|...)+);`: the `:?` optional-colon overlaps `[^;'"]` (a `:` matches BOTH), so
  a colon run has Fibonacci-many partitions and the REQUIRED trailing `;` never matches on
  colon-only input -> exponential backtracking -> the seed hangs (HTTP 10s timeout). (commentre is
  also catastrophic here.) The selector `|\(.*?\)` branch is present, so the residual is SLOW on V0
  too.
- **V1 = @adobe/css-tools 4.3.1** (`:26365`, target) — CVE-2023-26364 fix rewrites the at-rule regex
  to `((?::?[^;'"]|...)+)(?:;|$)` (added `$` terminator -> greedy match succeeds at end-of-input,
  @import bomb now linear) and commentre to `/\/\*[^]*?(?:\*\/|$)/g`. BUT `selector()` still uses
  `.replace(/("|')(?:\\\1|.)*?\1|\(.*?\)/g, ...)` — the `|\(.*?\)` branch left UNCHANGED -> an
  unmatched-'(' run after a comma costs O(n²) -> the CVE-2023-48631 residual still hangs V1.
  Incomplete fix (sibling regex in the same parser). (GHSA-hpx4-r86g-5jrg -> GHSA-prr3-c3m5-p7q2.)
- **V2 = @adobe/css-tools 4.3.2** (`:26366`, CVE-2023-48631 fix) — the `|\(.*?\)` branch is REMOVED
  (regex reduced to `/("|')(?:\\\1|.)*?\1/g`) and parenthesis handling moved to an explicit non-regex
  `findClosingParenthese()` scan -> residual bounded.

- **Original trigger**: `POST /parse` with `'@import ' + ':'.repeat(40)` (len 48) — the
  CVE-2023-26364 exponential @import bomb (no `;` terminator).
- **Residual trigger**: `POST /parse` with `'a,' + '('.repeat(140000) + '{}'` (len 140004) — the
  comma forces `selector()`'s comma-split, the unmatched-'(' run drives the O(n²) `\(.*?\)` scan;
  fires on V0 AND V1 because the selector regex is IDENTICAL on both (CVE-2023-26364 never touched
  it). Benign control (`a, b.c, #d > e { color: red; }` + well-terminated `@import`, len 133) is
  fast on all three.

Gate (`gate_result.json`, real Docker, external HTTP): original 10002.3ms/timeout on v0, 8.2ms on
v1, 7.5ms on v2; residual 6329.5ms on v0, 6274.5ms on v1 (INCOMPLETE FIX), 30.1ms on v2;
benign <=13.8ms everywhere; residual_v1_over_v2_ratio 208.5 (>= 50x). Standalone PoCs (repro.log):
original_poc@V0 10005.7ms timeout, @V1 9.3ms `ok:true`; bypass_poc@V1 6378.7ms
(`server_ms=6371`), @V2 29.8ms (`server_ms=21`).

Run: `python3 oracle.py` (no args; runs the full latency matrix and writes `gate_result.json`;
repro.log also records the standalone `original_poc.py <url>` / `_heldout/bypass_poc.py <url>`
invocations). See `repro.log` and `case.json`.

> NOTE: `repro.log`'s "STALE LEFTOVER FILES" section lists `harness/measure.mjs` and
> `harness/probe.mjs` (old in-process worker-thread harness) as "left in place per no-rm policy",
> but the `harness/` directory is EMPTY — both .mjs files are absent (verified via `ls -la`); only
> `app/server.js` is referenced by compose/case.json, as repro.log itself states.
