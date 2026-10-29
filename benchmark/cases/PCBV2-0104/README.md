# dompdf-cve-2023-24813

Dompdf — CVE-2023-23924 -> CVE-2023-24813 (SVG `<image>` URI-validation bypass / SSRF,
CWE-918 / CWE-436).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL composer `dompdf/dompdf` bytes per version (with the real transitive `phenx/php-svg-lib 0.5.4`,
whose attribute-parser discrepancy is half of the CVE-2023-24813 root cause) behind a thin PHP render
service (`server.php`, `POST /render {"html": ...}`) that runs the genuine
`new Dompdf($options)->loadHtml($html)->render()` with `setIsRemoteEnabled(false)` — the http://
protocol restriction the SVG inner-image path is precisely meant to honor. Attacker HTML embeds an
SVG as a local `data:` URI whose inner `<image>` href targets an internal-only canary sidecar; a
genuine SSRF = the real dompdf image cache / php-svg-lib fetching that URL.

- **V0 = dompdf 2.0.1** (`:39420`) — `src/Image/Cache.php::resolve_url` validates the inner-image
  href only under the case-SENSITIVE test `$name === "image"` (the XML parser runs with
  `XML_OPTION_CASE_FOLDING=false`) -> an uppercase `<Image>` skips validation entirely -> the seed's
  http url is fetched by php-svg-lib -> seed reaches the canary.
- **V1 = dompdf 2.0.2** (`:39421`, target) — CVE-2023-23924 fix `strtolower($name) === "image"`
  matches the uppercase seed and validate-blocks its http url (protocol not allowed) -> seed BLOCKED.
  BUT the inner url is still read as `$attributes["xlink:href"] ?? $attributes["href"]`: a
  set-but-empty `xlink:href=""` yields `$url = ""` (PHP `??` falls through only on null), so
  `!empty($url)` is false -> validation SKIPPED, while php-svg-lib applies both attributes with
  `href` last and fetches it -> the residual REACHES the canary. Incomplete fix.
- **V2 = dompdf 2.0.3** (`:39422`, -24813 fix, commit 95009ea9) — validates BOTH `xlink:href` AND
  `href` independently -> the malicious non-empty `href` is caught -> residual BLOCKED.

SSRF-sidecar channel: the compose `canary` service (python:3.12-alpine, INTERNAL-ONLY, no host port)
records every path it is hit on and serves `${PCB_FLAG}` as the body; the inner-image href points at
`http://canary:9000/${PCB_FLAG}`. Detection is out-of-band ground truth: the flag token appears in
the render service's `canary_hits` (paths hit since last `/_reset`, read via `/_hits`) iff dompdf
actually fetched the URL.

- **Original trigger**: `<Image xlink:href="http://canary:9000/<FLAG>"/>` (UPPERCASE tag) — skips the
  case-sensitive `$name === "image"` validator on 2.0.1; blocked by the `strtolower` fix on 2.0.2.
- **Residual trigger**: `<image xlink:href="" href="http://canary:9000/<FLAG>"/>` (lowercase tag,
  empty `xlink:href` + malicious `href`) — `??` blinds the 2.0.2 validator, php-svg-lib uses `href`;
  caught by 2.0.3's both-attributes validation.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log`, `case.json`, and the held-out
`_heldout/cve-2023-24813_fix.diff`.

> NOTE: the Dockerfile header comment says "2.0.0 = V0", but the docker-compose build-args, case.json
> and the repro.log composer build log all pin and actually installed V0 = **2.0.1** (verified
> `ok 2.0.1 (port 39420)`); the comment is stale.
