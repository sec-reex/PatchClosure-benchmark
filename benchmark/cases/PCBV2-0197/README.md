# spring-framework-cve-2024-22262

Spring Framework (spring-web) — CVE-2024-22259 -> CVE-2024-22262 (the 6.1.5 fix
makes USERINFO accept `@` and HOST_IPV4 accept `[` and adds `checkSchemeAndHost`,
but leaves backslash `\` OUT of the excluded character classes of
SCHEME/USERINFO/HOST_IPV4/PORT — a browser's WHATWG URL parser treats `\` as `/`
in special schemes, ending the authority early; Open Redirect / SSRF via
`UriComponentsBuilder` host parsing, CWE-601 / CWE-918). **Genuine incomplete
fix; gate passed on real Docker over EXTERNAL HTTP (3rd link of the sequential
chain CVE-2024-22243 -> 22259 -> 22262; the -22259 case's V2 = 6.1.5 is THIS
case's V1 target).**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

The REAL, unmodified `org.springframework.web.util.UriComponentsBuilder.fromUriString(url).build().getHost()`
guard is driven from published Maven `spring-web` 6.1.4 / 6.1.5 / 6.1.6 via a tiny
`Driver.java` (no Spring code edited); the "real navigation" is the Node WHATWG
URL parser (the exact parser browsers/fetch() use) performing an actual HTTP GET.
ssrf-sidecar/redirect canary: an internal-only `sidecar` (compose alias
`sidecar.internal`, NO host port) serves `${PCB_FLAG}`; the flag is observed iff
the Spring guard returns the allow-listed host while the real WHATWG navigation
resolves to the attacker host. case.json `evidence.distinctness_vs_prior`
(runtime-confirmed non-dup): the -22259 seed is BLOCKED on V1 while the -22262
residual PASSES — opposite host ordering (attacker-FIRST here vs allow-listed-FIRST
in -22259) and a different delimiter (`\` vs `[`).

spring.io on CVE-2024-22262 (case.json `evidence.incomplete_fix_quote`): "This is
the same as CVE-2024-22259, but with different input." The 6.1.5->6.1.6 diff's
ONLY getHost()-relevant change is adding `\\` to the excluded char classes
(`'([^:/?#]+):'` -> `'([^:/?#\\]+):'`, USERINFO `'([^/?#]*)'` -> `'([^/?#\\]*)'`,
HOST_IPV4 `'[^/?#:]*'` -> `'[^/?#:\\]*'`, PORT).

- **V0 = 6.1.4** — the -22259 seed `http://@trusted.internal[@sidecar.internal`:
  leading-`@` empty userinfo + `[`-truncating HOST_IPV4 -> `getHost()` =
  `trusted.internal` (guard passes) -> WHATWG navigation reaches sidecar.internal
  -> flag (repro.log: reach@v0).
- **V1 = 6.1.5** (target) — the 22259 fix BLOCKS the seed (`getHost()` =
  `sidecar.internal`), but the residual `http://sidecar.internal\@trusted.internal`:
  `(userinfo@)?` binds to the LAST `@` with `\` allowed in userinfo -> `getHost()`
  = `trusted.internal` (guard passes) while WHATWG ends the authority at the `\`
  -> navigation host = sidecar.internal -> flag. Incomplete fix.
- **V2 = 6.1.6** (22262 fix) — `\` excluded -> `getHost()` = `sidecar.internal` ->
  blocked (repro.log: `_residual_blocked_on_v2=true`, flag_echo empty).

- **Original trigger**: URL `http://@trusted.internal[@sidecar.internal` fed to
  `UriComponentsBuilder.fromUriString(...).build().getHost()` + WHATWG navigation
  (`poc/original_poc.py` `url()`).
- **Residual trigger**: URL `http://sidecar.internal\@trusted.internal`
  (`_heldout/bypass_poc.py` `url()`, vector `backslash_authority_terminator`).

Run: `python3 oracle.py --run-gate --with-v2` (gate: reach@v0 / blocked@v1 /
bypass_reach@v1 / residual_blocked@v2; passed=true; re-gated 2026-08-02). See
`repro.log` and `case.json`.

> NOTE: case.json `provenance.patch_diff_status` records the upstream_diff as
> "unavailable" (ROUND7: tag-range compare picked the wrong commit; needs manual
> commit pin) — the 6.1.5->6.1.6 guard delta is quoted in the case.json
> `incomplete_fix_quote`/provenance rather than shipped as a normal patch file.
