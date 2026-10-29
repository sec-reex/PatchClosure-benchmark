# avideo-cve-2026-33500

AVideo (WWBN/AVideo) — CVE-2026-27568 -> CVE-2026-33500 (stored XSS, incomplete fix).

**Run mode** `real-app-http`. Each v0/v1/v2 Docker image `git clone`s the REAL github.com/WWBN/AVideo
tree at the exact CVE commit and serves it; the sink runs out of the cloned repo files (NO source-lift).
- v0 = `3905f03df0f0d05c44715419d7535e4dc3649e76` (pre-27568: plain Parsedown 1.7.4, no sanitizer)
- v1 = `f154167251c9cf183ce09cd018d07e9352310457` (27568 fix = TARGET; `ParsedownSafeWithLinks`, no `inlineLink` override)
- v2 = `3ae02fa240939dbefc5949d64f05790fd25d728d` (33500 fix; adds `inlineLink()` override)

**Sink** comment markdown rendering `markDownToHTML()` -> `<a href>` (`objects/functionsSecurity.php`),
reached over EXTERNAL HTTP: `POST /comment` stores the attacker comment, `GET /` renders it via the
REAL sink (the page the victim views). `avideo_sink.php` is thin glue that `require`s the cloned
`vendor/autoload.php` (REAL Parsedown) + `objects/functionsSecurity.php` (REAL sink) and calls the REAL
`markDownToHTML()` — it re-implements nothing.
**Guard (V1, CVE-2026-27568 fix)** `ParsedownSafeWithLinks` overrides `inlineMarkup()`/`sanitizeATag()`
with a scheme whitelist `/^(https?://|mailto:|/|#)/i` on RAW HTML `<a>`, safeMode OFF.
**Residual (CVE-2026-33500)** markdown link `[x](javascript:...)` is parsed by Parsedown core
`inlineLink()`, which V1 does NOT override -> `javascript:` href survives. Fixed V2 by overriding
`inlineLink()` with the same whitelist.

Canary = **xss-exfil**: a headless chromium victim carries `${PCB_FLAG}` in a cookie and clicks the
rendered comment link (CVE is UI:R); an executable `javascript:` href reads `document.cookie` and
posts it to an internal callback -> proves JS EXECUTION. `gate_passed` on real Docker — see `repro.log`.

Run: `PCB_FLAG=$(python3 -c 'import secrets;print("PCBFLAG_"+secrets.token_hex(16))') \
docker compose --profile v0 --profile v1 --profile v2 up -d` then `python3 oracle.py --gate`.

## Stale files (superseded by the real-app rebuild; kept per the no-rm directive)
`app.php`, `render.php` — the OLD hand-written faithful-core harness that re-implemented the sink
(BANNED source-lift). No longer referenced by `docker-compose.yml` / `Dockerfile` / `case.json`.
`BUILD_TODO.md`, `__pycache__/` — stale scaffolding. None are used by the current build.

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
