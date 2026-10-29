# spring-uricomponentsbuilder-openredirect-cve-2024-22259

Spring Framework (spring-web) — CVE-2024-22243 -> CVE-2024-22259 (URL-parser host-validation bypass /
open redirect, CWE-601).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Java HTTP service (`Harness`, JDK `com.sun.net.httpserver.HttpServer`) exposes
`GET /redirect?url=<urlencoded target>` (`Harness.approveRedirect`). It parses the target with the REAL,
unmodified published `UriComponentsBuilder.fromUriString(url).build().getHost()` — the parser is NOT
lifted or re-implemented; the harness depends only on the genuine spring-web JAR from Maven Central
(build-arg `SPRING_VER`), and the app code is byte-identical across the three images, so the only
variable is the JAR. If `getHost()` equals the allowlist host `trusted.internal`, the harness approves
and emits `Location: <url>` with the RAW target unchanged — exactly the vulnerable pattern the spring.io
advisories describe; otherwise 403 with a body that does not echo the target. Same sink, same
regex-constant fix mechanism (`USERINFO_PATTERN` / `HOST_IPV4_PATTERN`); the advisory calls CVE-2024-22259
"This is the same as CVE-2024-22243, but with different input."

- **V0 = spring-web 5.3.31** (`:42430`) — `USERINFO_PATTERN="([^@\[/?#]*)"`, `HOST_IPV4_PATTERN="[^\[/?#:]*"`:
  userinfo cannot cross `[`, so the seed parses `getHost()=="trusted.internal"` -> allowlist passes -> 302
  Location carries the flag, off-origin to attacker.test. (V0 mis-extracts BOTH inputs.)
- **V1 = spring-web 5.3.32** (`:42431`, target) — CVE-2024-22243 fix (commit `7ec5c994`, "Update user info
  pattern") only removes `[` from userinfo (`"([^@/?#]*)"`), `HOST_IPV4_PATTERN` unchanged: the seed now
  yields userinfo=`trusted.internal[`, `getHost()=="attacker.test"` -> 403 BLOCKED — but the host class
  still terminates on `[` and userinfo still cannot contain `@`, so the residual (leading `@` + `[`) still
  parses `getHost()=="trusted.internal"` -> the flag still reaches. Incomplete fix.
- **V2 = spring-web 5.3.33** (`:42432`, CVE-2024-22259 fix) — commit `297cbae2` ("Extract reusable
  checkSchemeAndPort method") removes `@` from userinfo (`"([^/?#]*)"`) AND `[` from
  `HOST_IPV4_PATTERN="[^/?#:]*"` -> both inputs extract `attacker.test` -> residual BLOCKED.

Redirect-canary channel: the per-run `${PCB_FLAG}` rides in the redirect target's QUERY STRING
(`url=http://trusted.internal[@attacker.test/?<FLAG>` / `url=http://@trusted.internal[@attacker.test/?<FLAG>`);
the flag appears verbatim in the emitted `Location` header iff the guard approved steering off-origin to
attacker.test. A blocked request returns 403 with no Location, so the flag never appears. Nothing planted
in app code.

- **Original trigger**: `http://trusted.internal[@attacker.test/?<FLAG>` — on 5.3.31 the userinfo regex
  stops at `[` (before any `@`), so `getHost()=="trusted.internal"` while a browser resolves everything
  before the LAST `@` as userinfo -> real host `attacker.test`.
- **Residual trigger**: `http://@trusted.internal[@attacker.test/?<FLAG>` — on 5.3.32 the leading `@` is
  consumed as an EMPTY userinfo, the host parse restarts at `trusted.internal[` and `HOST_IPV4` still stops
  at `[` -> `getHost()=="trusted.internal"` again (CVE-2024-22259: same issue, different input).

Run: `python3 oracle.py --run-gate` (gate, flag `PCBFLAG_eadaf9daac97cb95eab7f0804e0705a0`
per repro run: ORIGINAL@v0 302 FLAG / ORIGINAL@v1 403 / RESIDUAL@v1 302 FLAG /
RESIDUAL@v2 403; negative control plain attacker.test 403 on all three;
passed=true). See `repro.log` and `case.json`.
