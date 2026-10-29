# koa-cve-2025-62595

koa (npm, koajs) — CVE-2025-54420 -> CVE-2025-62595 (Referrer-based `back()` open redirect: the
`startsWith('/')` branch skips the origin check, so a protocol-relative `//host` passes, CWE-601).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL npm koa bytes per profile (Dockerfile build-arg `KOA_VERSION`, `node:20-slim`) wrapped by a
minimal REAL Koa app (`app.mjs`): `GET /redirect` calls the genuine `ctx.response.back('/')`; the
redirect decision is made ENTIRELY by the real library (`lib/response.js :: back()`, reading the
client-supplied `Referer` header). Observable = the emitted 302 `Location` header. Same sink, same
fix mechanism; the bypass advisory GHSA-g8mr-fgfg-5qpc states explicitly that it "affects the code
referenced in GHSA-jgmv-j7ww-jx2x (CVE-2025-54420)". `patch_real.diff` is the real upstream 3.0.1
fix (commit `422c551`).

- **V0 = koa 3.0.0** (`:41310`) — `back()` is literally
  `const url = this.ctx.get('Referrer') || alt || '/'; this.redirect(url)` — ANY Referrer, no origin
  check -> the original absolute-Referer vector reaches the flag.
- **V1 = koa 3.0.1** (`:41311`, target) — the CVE-2025-54420 fix adds an origin check for ABSOLUTE
  referrers (`new URL(referrer, ctx.href).host === ctx.host`) but redirects ANY Referrer that
  `startsWith('/')` VERBATIM with no check -> the absolute seed is BLOCKED (`Location: /`), yet a
  PROTOCOL-RELATIVE `//attacker.pcb/<FLAG>` also startsWith('/'), takes the unchecked branch, and
  browsers resolve `Location: //attacker.pcb/...` as the absolute off-origin URL -> the residual
  still reaches the flag. Incomplete fix.
- **V2 = koa 3.0.3** (`:41312`, -62595 fix) — the `startsWith('/')` early-return is DELETED; every
  Referrer now flows through `new URL(referrer, ctx.href)` + the `url.host === ctx.host` origin
  check -> residual BLOCKED (`Location: /`).

Redirect-canary: the per-run `${PCB_FLAG}` is ONLY the path segment of the attacker redirect target
(`http://attacker.pcb/<FLAG>` / `//attacker.pcb/<FLAG>`); nothing is planted server-side (the app
carries no flag at all — the observable is purely koa's own output). The flag surfaces iff koa
approves and emits the off-origin `Location`; a block falls back to `Location: /` (no flag).
Negative control: legit same-origin relative `Referer: /dashboard` -> `Location: /dashboard`
allowed on ALL THREE versions.

- **Original trigger**: `GET /redirect` with `Referer: http://attacker.pcb/<FLAG>` (absolute URL) ->
  flag on V0 (302 `Location: http://attacker.pcb/<FLAG>`); BLOCKED on V1/V2 (`Location: /`).
- **Residual trigger**: `GET /redirect` with `Referer: //attacker.pcb/<FLAG>` (protocol-relative; koa's
  `redirect()` only re-formats `^https?://` values, so the Location is set verbatim) -> flag on V1
  (302 `Location: //attacker.pcb/<FLAG>`, BYPASS); BLOCKED on V2 (`Location: /`).

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.
