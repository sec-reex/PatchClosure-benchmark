# shell-quote-cve-2026-9277

shell-quote (npm, ljharb) — CVE-2021-42740 -> CVE-2026-9277 (OS command injection via INCOMPLETE
metacharacter neutralization in the same `quote()` function, CWE-78). **Genuine incomplete fix; gate
passed on real Docker over EXTERNAL HTTP (4-way closure).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published shell-quote bytes per version, installed side-by-side via npm aliases (1.7.2 / 1.7.3 /
1.8.4, verified in-container) on node:20-slim. The harness (`harness.mjs`) exposes
`GET /probe?tokens=<JSON>`: it builds `"echo ok " + shellQuote.quote(tokens)` and runs it via
`child_process.exec('/bin/sh -c ...')` — quote()'s per-token escaping is the boundary. Canary is
benign flag-read only: `entrypoint.sh` writes `${PCB_FLAG}` to `/canary/flag.txt` (outside the app)
and plants two no-arg readers that just `cat` it — `/canary/rf`, and a PATH command literally named
`:;rf` (entrypoint.sh:12-18). No real payload; detection = flag token substring in the command
`output`.

`patch_real.diff` is the CVE-2021-42740 first-fix (1.7.2..1.7.3, `index.js` `exports.quote`): the
Windows drive-letter prefix class `([A-z]:)?` -> `([A-Za-z]:)?` in the STRING else-branch only —
`[A-z]` spans ASCII 90..97, which includes BACKTICK(96), so group 1 swallowed a leading `` `: `` and
re-emitted it UNESCAPED via `$1`. The fix left the OBJECT op-branch
(`s.op.replace(/(.)/g,'\\$1')`) untouched — and JS `.` does not match line terminators, which is
exactly what CVE-2026-9277 / GHSA-w7jw-789q-3m8p reports.

- **V0 = shell-quote 1.7.2** (`:39900`) — string else-branch `[A-z]` bug: token `` `:;rf`:; `` keeps its
  backticks -> /bin/sh runs the colon-glued command substitution `:;rf` -> the planted PATH reader
  cats the flag -> seed reaches.
- **V1 = shell-quote 1.7.3** (`:39901`, target) — the 42740 fix BLOCKS the backtick seed (escaped
  literal echo), but the SAME quote() still leaves a NEWLINE in an OBJECT op-token unescaped; the raw
  newline is a POSIX command separator -> line 2 runs `/canary/rf` -> the CVE-2026-9277 residual
  reads the flag. Incomplete fix.
- **V2 = shell-quote 1.8.4** (`:39902`, 0691 fix) — op-tokens validated against the OPS allowlist +
  line-terminator rejection -> `quote([{op:';\n/canary/rf'}])` THROWS TypeError before any command is
  built -> blocked (original also blocked; benign controls `{op:'&&'}` and a plain-string newline
  token stay neutralized on all versions).

- **Original trigger**: `tokens = ["`:;rf`:;"]` — a STRING token whose leading `` `: `` is swallowed by
  V0's over-broad `[A-z]:` class (`poc/original_poc.py` `candidate()`).
- **Residual trigger**: `tokens = [{"op": ";\n/canary/rf"}]` — an OBJECT op-token whose newline
  survives V1's `s.op.replace(/(.)/g,'\\$1')` (`_heldout/bypass_poc.py` `candidate()`); the injected
  line must be a single word because quote() also backslash-escapes spaces.

> NOTE: per case.json `source_verified_caveat`, the two flaws sit on DIFFERENT internal branches of
> the SAME `quote()` (string else-branch vs object op-branch), and the seed is only realizable
> through the planted PATH command named `:;rf` (the `[A-z]:` bypass always re-emits the backtick
> colon-glued, so arbitrary multi-arg RCE is not reachable) — recorded here as the dossier itself
> states. Package layout also differs: `exports.quote` in 1.7.x `index.js` vs
> `module.exports=function quote` in 1.8.4 `quote.js`.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(live gate: v0 seed flag / v1 seed blocked / v1 residual flag / v2 both blocked).
