# semver_regex_prerelease_redos

semver-regex (npm, sindresorhus) — CVE-2021-3795 -> CVE-2021-43307 (ReDoS / catastrophic regex
backtracking, CWE-1333). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`app/server.js`) exposes `POST /check {version}` running the REAL published
npm package synchronously on the event loop: `const ok = semverRegex().test(req.body.version)` —
the documented sink. A catastrophic input wedges Node's single thread, so the ReDoS is observed as
server-side latency of an EXTERNAL request (dos-threshold oracle: ReDoS iff latency > T_SLOW 2000ms
or 10s read-timeout; bounded iff < T_FAST 300ms). No flag token file; a `watchdog.py` sidecar
(`:28138`) releases the per-run `PCB_FLAG` only once the event loop is wedged. The oracle probes each
payload against a FRESH server (kill + `up -d` between probes; cpus=1.0, mem 512m) because a running
regex cannot be interrupted.

`patch_real.diff` is the upstream CVE-2021-3795 fix (commit `11c66245f4e1976dccc52977ed183696a21a3fd7`,
3.1.3 / GHSA-44c6-4v22-4mhx): bounds the numeric fields (`\d{0,9}`), makes identifiers lazy (`*?`),
swaps the trailing anchor for `\b`, and CAPS the repetitions with nested `{0,100}` / `{1,200}`. Those
two nested greedy `{0,100}` bounds are themselves exponentially backtrackable (JFrog XRAY-211349 /
GHSA-4x5v-gmq8-25ch) — the 3.1.4 fix simply makes every bound lazy (`{0,100}?`, `{1,200}?`). Textbook
same-sink sequential-patch incomplete fix. (Per the analysis, GitHub's `3.1.3` tag was later moved to
the lazy version — the registry package is authoritative.)

- **V0 = semver-regex 3.1.1** (`:28131`) — unbounded greedy pre-release identifier `[\\da-z-]*[a-z-][\\da-z-]*`
  inside an unbounded `(?:\\.(...))*` -> the `a-a.`-run seed blows up exponentially.
- **V1 = semver-regex 3.1.3** (`:28133`, target) — the 3795 rewrite BLOCKS the seed (14.2ms), but its
  own nested greedy `{0,100}` groups create a NEW exponential path -> the CVE-2021-43307 residual
  hangs (10s timeout). Incomplete fix.
- **V2 = semver-regex 3.1.4** (`:28134`, 43307 fix) — every bounded repetition lazy -> residual fast
  again (6.7ms; benign `1.2.3-alpha.1` fast on all three).

- **Original trigger**: `"1.2.3-" + "a-a." * 22 + "!"` (len 95, POSTed to `/check`) — the trailing `!`
  fails V0's end anchor, forcing catastrophic backtracking over the dotted run of ambiguous
  pre-release identifiers (`poc/original_poc.py` `PAYLOAD`).
- **Residual trigger**: `"0.0.1-" + "-.--" * 14 + " "` (len 63, POSTed to `/check`) — the trailing
  space fails V1's `\b` anchor and explodes the nested `{0,100}` bounds
  (`_heldout/bypass_poc.py` `PAYLOAD`; JFrog's construction, asserted verbatim in 3.1.4's own test).

> NOTE: case.json's V0 regex text ends with the lookahead `(?=$|\s)`, while `patch_real.diff`'s
> pre-image and the V0 quote in INCOMPLETE_FIX_ANALYSIS.md end with `\\b`. The seed mechanism
> (trailing `!` fails the end anchor) holds under either anchor; recorded here as found.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log`, `gate_result.json` (original
10001ms@v0 / 14ms@v1; residual 10001ms@v1 / 6.7ms@v2; residual_v1_over_v2_ratio 1492.7; passed=true)
and `case.json`.
