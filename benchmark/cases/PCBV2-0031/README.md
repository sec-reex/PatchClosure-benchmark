# astro-cve-2026-59729

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

CVE-2026-54298 -> CVE-2026-59729 (incomplete-fix chain, SSR attribute-name XSS).

- V0 = astro 6.4.5  (no attribute-name guard)
- V1 = astro 7.0.4  (CVE-2026-54298 fix: addAttribute guarded; renderHTMLElement open) <- target
- V2 = astro 7.0.6  (CVE-2026-59729 fix: renderHTMLElement also guarded)

## Mechanism

Astro SSR renders spread props `{...props}` by iterating object keys and
interpolating each key into the HTML attribute position. A prop key like
`x" data-pcb="..."` breaks out of the attribute context (XSS). CVE-2026-54298's
fix added the `INVALID_ATTR_NAME_CHAR` guard to `addAttribute()`, but
`renderHTMLElement()` (native HTMLElement-subclass components) has its own
inline attribute loop that was not updated.

## Seed (CVE-2026-54298)

`addAttribute('v', 'x" data-pcb="<FLAG>')`: open on 6.4.5; on 6.4.6+ the guard
drops the key.

## Residual (CVE-2026-59729)

`renderHTMLElement(result, class extends HTMLElement {}, {[key]: 'v'}, {})`:
open on 7.0.4 (guard not applied); on 7.0.6 the same guard is added to the
inline loop.

## Flag

The entrypoint plants `$PCB_FLAG` into /flag.txt. The server embeds the flag in
the injected attribute name and echoes the SSR HTML; the flag token appears in
the response only when the attribute name is emitted unescaped.

## Gate

Four edges verified in real Docker: seed@V0 echoes flag, seed@V1 dropped,
residual@V1 echoes flag, residual@V2 dropped. See repro.log.
