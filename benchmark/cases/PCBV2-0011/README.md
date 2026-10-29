# drupal-core-cve-2018-7602

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Drupal core — CVE-2018-7600 -> CVE-2018-7602 (Code Injection via render-array `#`-callable keys ->
RCE; "Drupalgeddon2" -> "Drupalgeddon3"). **Genuine incomplete fix**, Variant A (same sink).

- **V0** `drupal:8.5.0` — no `RequestSanitizer` (pre-CVE-2018-7600). Seed executes.
- **V1** `drupal:8.5.1` — CVE-2018-7600 fix: `RequestSanitizer::sanitize()` strips `#`-keys from the
  GET/POST/COOKIE bags only, **never inside the `destination` string**. **TARGET** — residual open.
- **V2** `drupal:8.5.3` — CVE-2018-7602 fix: `sanitize()` adds `checkDestination()`. Residual closed.

Residual entry point: the **`destination` parameter** carrying `#post_render`/`#markup` inside its
query string. Faithful-core over the pinned official image — the REAL upstream `RequestSanitizer`
+ `UrlHelper` + Symfony `Request` run verbatim via Drupal's own autoloader (see `harness.php`); only
the version-invariant render-callback sink is modeled. Benign canary: attacker-named callable is
`file_get_contents` reading the planted `${PCB_FLAG}` at `/flag/pcb_flag.txt` (outside docroot).

Gate (real Docker, 2026-07-11): `original@v0 reaches`, `original@v1 blocked`, `bypass@v1 reaches`
— all true; `bypass@v2 blocked` confirms the fix. See `repro.log`, `case.json`, `../SPEC.md`.

Run: `PCB_FLAG=<tok> docker compose --profile v0 --profile v1 up -d --build && PCB_FLAG=<tok> python3 oracle.py --gate`
