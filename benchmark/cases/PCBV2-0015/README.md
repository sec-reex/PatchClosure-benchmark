# postcss_sourcemap_redos

postcss (npm) — CVE-2021-23368 -> CVE-2021-23382 (ReDoS / catastrophic regex backtracking in the
`/*# sourceMappingURL=... */` source-map annotation regex, CWE-1333). **Genuine incomplete fix; gate
passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`app/server.js`) exposes `POST /process {css}` running the REAL published
package synchronously on the event loop:
`postcss.parse(css, { from: '/tmp/in.css', map: { prev: true } })` -> `Input` -> `PreviousMap` ->
`loadAnnotation(css)` -> `css.match(/\/\*\s*# sourceMappingURL=...\*\//gm)` in lib/previous-map.js —
the documented sink. A catastrophic input wedges Node's single thread, so the ReDoS is observed as
server-side latency of an EXTERNAL request (dos-threshold oracle: ReDoS iff latency > T_SLOW 2000ms
or 10s read-timeout; bounded iff < T_FAST 300ms). No flag token file; a `watchdog.py` sidecar
releases the per-run `PCB_FLAG` once the event loop is wedged. The oracle probes each payload against
a FRESH server (kill + `up -d`; cpus=1.0, mem 512m) because a running regex cannot be interrupted.

`patch_real.diff` is the upstream CVE-2021-23368 fix (commits `8682b1e4...` + `b6f3e4d5...`, 8.2.10):
it only REMOVES the `\s*` sub-pattern before `\*/` in both `loadAnnotation` and `getAnnotationURL`
(`.*\s*\*/` -> `.*\*/`), killing the `.*`/`\s*` space-partition ambiguity — but leaves the greedy
`.*` intact. Under the `/g` scan, every repeated `/*# sourceMappingURL=` start position restarts a
full scan-to-EOL-and-backtrack for a `*/` that never appears -> O(n²) — which is exactly
CVE-2021-23382 ("caused mainly by the sub-pattern `\/\*\s*# sourceMappingURL=(.*)`", per the Snyk
quote in case.json). The 8.2.13 fix replaces `.*` with the tempered-greedy
`(?:(?!sourceMappingURL=).)*`, which cannot cross a repeated prefix.

- **V0 = postcss 8.2.9** (`${PORT_V0_0}` -> 3000; PoC default `:28209`) — `.*` + `\s*` ambiguity over
  the space run -> the whitespace-pad seed blows up exponentially (10s timeout).
- **V1 = postcss 8.2.10** (`${PORT_V1_0}` -> 3000; case.json v1 base_url `http://127.0.0.1:28210`,
  target) — the 23368 fix BLOCKS the whitespace seed (8.1ms) but the greedy `.*` remains -> the
  repeated-prefix residual hangs (10s timeout). Incomplete fix.
- **V2 = postcss 8.2.13** (`${PORT_V2_0}` -> 3000, 23382 fix) — tempered-greedy token -> residual fast
  again (12.7ms; benign `a{}/*# sourceMappingURL=data:...base64,e30= */` fast on all three).

- **Original trigger**: `"a{}/*# sourceMappingURL=" + " " * 90000 + "!"` (len 90025, POSTed to
  `/process`) — whitespace pad with NO closing `*/`, exercising the `.*`/`\s*` ambiguity
  (`poc/original_poc.py` `PAYLOAD`).
- **Residual trigger**: `"a{}" + "/*# sourceMappingURL=" * 24000 + "!"` (len 504004, POSTed to
  `/process`) — repeated annotation prefix with no `*/`; the greedy `.*` backtracks at every `/*`
  start under the `/g` scan (`_heldout/bypass_poc.py` `PAYLOAD`; Snyk's `build_attack` construction).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log`, `gate_result.json` (original
10001.9ms@v0 / 8.1ms@v1; residual 10002.0ms@v1 / 12.7ms@v2; residual_v1_over_v2_ratio 787.6;
passed=true) and `case.json`.
