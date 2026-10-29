# nuxt-og-image-isblockedurl

nuxt-og-image (npm, nuxt-modules/og-image) — GHSA-pqhr-mp3f-hrpp (no CVE alias) → CVE-2026-44589
(SSRF: incomplete IPv6 denylist in `isBlockedUrl()` — hex IPv4-mapped loopback slips the prefix
list — plus no redirect re-validation, CWE-918).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published nuxt-og-image (6.2.4/6.2.5/6.4.9 by `OGI_VER` build-arg) inside a REAL production
Nuxt 4.4.5 app (`npm i nuxt@4.4.5 nuxt-og-image@<ver> satori@0.26`; `nuxt build`;
`node .output/server/index.mjs` — `import.meta.dev=false`, so the guard is ACTIVE). No module source
is lifted. External trigger through the module's own og-image endpoint: `GET /ssrf?avatar=<vector>`
(`app/pages/ssrf.vue`) bakes the attacker URL into the generated og:image URL
(`/_og/d/c_Ssrf,src_~<b64>,...png`); fetching that URL (rendered as `og.svg`, `debug:true`) makes the
imageSrc plugin run the REAL per-version `isBlockedUrl(<vector>)` and, if allowed, `$fetch(<vector>)`,
base64-inlining the response into the og-image SVG. The SSRF destination is a co-located
loopback-only flag sidecar (`sidecar.mjs`, FLAG_PORT=9111, bound to `::`, NO published host port)
serving a tiny SVG with `${PCB_FLAG}` in `<desc>`; the oracle base64-decodes the inlined data URI(s).
`entrypoint.sh` strips `PCB_FLAG` from the Nuxt render process env, so the flag surfaces only via a
genuine loopback fetch.

- **V0 = nuxt-og-image 6.2.4** (`:39610`) — NO `isBlockedUrl` at all (denylist not yet introduced) →
  the bare-loopback seed is fetched directly → flag.
- **V1 = nuxt-og-image 6.2.5** (`:39611`, target) — the GHSA-pqhr-mp3f-hrpp fix introduces
  `isBlockedUrl()` (blocks `localhost`/`*.localhost`, private IPv4 dotted + integer/hex +
  dotted-mapped via `RE_MAPPED_V4=/^::ffff:(\d+\.\d+\.\d+\.\d+)$/`, and IPv6 only where
  `bare === "::1" || startsWith("fc"|"fd"|"fe80")`) → the seed `http://[::1]:9111/` is BLOCKED
  (render 500, src deleted), but the hex-compressed IPv4-mapped loopback is not dotted and matches
  no IPv6 prefix → the residual still reaches loopback. Incomplete fix.
- **V2 = nuxt-og-image 6.4.9** (`:39612`, CVE-2026-44589 fix) — `isBlockedUrl` rewritten with full
  IPv6 expansion (`expandIPv6` → `isPrivateIPv6`: `::ffff:7f00:1` → `::ffff:127.0.0.1` → 127.x →
  private → BLOCKED) and adds `fetchWithRedirectValidation` (re-runs the check on every 30x hop) →
  residual BLOCKED.

- **Original trigger**: `avatar=http://[::1]:9111/` (bare IPv6 loopback; GHSA-pqhr-mp3f-hrpp form) —
  reaches on V0, blocked on V1 (`bare === "::1"`).
- **Residual trigger**: `avatar=http://[::ffff:7f00:1]:9111/` (hex-compressed IPv4-mapped loopback ==
  `::ffff:127.0.0.1`; CVE-2026-44589 primary bypass) — WHATWG URL normalization turns even the dotted
  spelling `[::ffff:127.0.0.1]` into this hex form, so both spell the V1 gap; reaches on V0 AND V1,
  blocked on V2.

Network-level proof (repro.log sidecar HIT log): V0 hit by both `::1` and `::ffff:127.0.0.1`; V1 hit
ONLY by `::ffff:127.0.0.1` (seed `::1` blocked); V2 no hits.

Run: `PCB_FLAG=... python3 oracle.py --gate` (profiles v0/v1/v2). See `repro.log`, `case.json`,
`docker-compose.yml`, `patch_real.diff` (the 6.2.4→6.2.5 upstream first-fix diff).

> NOTE: the original side of the pair has NO CVE identifier — GHSA-pqhr-mp3f-hrpp shows "No known
> CVE" (recorded in case.json `original_cve_note`); only the bypass side is a CVE. Two field-level
> oddities in case.json, recorded as found: `cve_pair.bypass_published` is "2026-11-01" (later than
> today, 2026-10-11), and the top-level `run_mode` is "real-app-http" while
> `execution.run_mode` says "real-service-http". Also, `patch_real.diff` bundles a
> `sanitizeProps (GHSA-mg36-wvcr-m75h)` unit test alongside the isBlockedUrl fix — a second
> advisory hardening shipped in the same 6.2.5 release.
