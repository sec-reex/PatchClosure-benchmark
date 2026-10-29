# url-parse-openredirect-2021-3664-2022-0691

url-parse (npm, unshiftio) — CVE-2021-3664 -> CVE-2022-0691 (Open Redirect via URL-parser confusion,
CWE-601). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL npm `url-parse` installed per profile via Dockerfile build-arg (1.5.1/1.5.2/1.5.9 on
node:20-slim); `harness.mjs` is a canonical safe-redirect endpoint, `GET /redirect?to=<url>`, calling
the genuine parser: `new UrlParse(to, SELF_ORIGIN)` then allowlist
`parsed.hostname === '' || === 'trusted.internal'` (harness.mjs:68-72). Approved -> redirect to the
RAW target (real 302 `Location` for header-safe targets; `<meta http-equiv=refresh>` body fallback
when Node refuses the control byte in a header); rejected -> 403 with a static body. Redirect-canary:
the per-run `${PCB_FLAG}` is used ONLY as the attacker redirect-host label
(`<FLAG>.evil.example`), so it surfaces in the emitted Location header / client-redirect body iff the
guard approved an off-origin steer. Nothing is planted in app code.

`patch_real.diff` is the upstream CVE-2021-3664 fix (1.5.1..1.5.2, commit `81ab967`): `slashes`
regex tightened from `:[\\/]+` to `://`, `isSpecial()` added, and `sanitize` now globally replaces
`\` with `/` for special schemes — closing the backslash-after-scheme seed but leaving `trimLeft`'s
whitespace class starting at `\x09` untouched, so a leading C0 control char (`\x08`) still makes the
library mis-read an absolute URL as relative.

- **V0 = url-parse 1.5.1** (`:41280`) — `https:\<host>` yields `hostname === ''` (mis-read as
  hostless/relative) -> guard approves -> seed flag in the 302 Location.
- **V1 = url-parse 1.5.2** (`:41281`, target) — the 3664 isSpecial/slash rework BLOCKS the backslash
  seed (403), but `trimLeft` still does not strip `\x00`-`\x08`: a leading `\x08` defeats scheme
  recognition, the URL resolves as RELATIVE against `SELF_ORIGIN` (hostname `trusted.internal`) ->
  guard approves -> CVE-2022-0691 residual flag in the client-redirect body. Incomplete fix.
- **V2 = url-parse 1.5.9** (`:41282`, 0691 fix, commit `0e3fb54`) — `trimLeft` broadened to
  `\x00`-`\x20` + CRHTLF strip -> `\x08` removed, hostname off-origin -> 403. Both blocked.
  (Intermediate 1.5.6/1.5.8 leave the residual open — case.json provenance.)

- **Original trigger**: `to = https:\<FLAG>.evil.example` (single backslash after the scheme;
  `poc/original_poc.py` `candidate()`) — browser reads it as `https://<FLAG>.evil.example`, library
  reads no host.
- **Residual trigger**: `to = \x08http://<FLAG>.evil.example` (leading BACKSPACE control char;
  `_heldout/bypass_poc.py` `candidate()`, the advisory's own `\b` construction) — WHATWG strips the
  `\x08` and navigates off-origin; 1.5.2 treats it as relative and approves.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json` (gate 2026-07-16:
backslash flag@v0 / blocked@v1; `\x08` flag@v1 / blocked@v2; plain-external blocked on all,
legit-relative allowed on all; passed=true).
