# wordpress-wp-super-cache-plugin-cve-2013-2011

WordPress WP Super Cache plugin — CVE-2013-2009 -> CVE-2013-2011 (the 1.3 fix's
`no_mfunc_in_comments()` guard zaps a comment only when the SAME comment carries
an opening AND a closing mfunc/mclude tag — splitting the pair across TWO comments
slips past the per-comment replace, and `wp-cache-phase2.php`'s page-buffer regex
`|<!--mfunc (.*?)-->(.*?)<!--/mfunc-->|is` still recombines them into executable
cache PHP; PHP code injection via mfunc comment tags baked into the page cache,
CWE-94 / CWE-116). **Genuine incomplete fix; gate passed on real Docker (Variant
A, same sink + same flag channel).**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

The REAL WP Super Cache plugin bytes per pinned wordpress.org version (1.2 /
1.3.1 / 1.3.2 zips fetched at build). Two generations of the environment coexist
in the case dir (see NOTE): the CURRENT `docker-compose.yml` boots full WordPress
(`wordpress:6.1.1-php7.4-apache` — PHP 8 cannot parse Super Cache 1.2's `$path{N}`
offsets — + mariadb + wp-cli) with the WHOLE plugin installed and activated by
`wp-entrypoint.sh`, triggered by a real guest `POST /wp-comments-post.php` and an
anonymous GET of the cached post; the audited run recorded in case.json/repro.log
executed the plugin's REAL `no_mfunc_in_comments()` guard and REAL phase2
mfunc->PHP sink verbatim behind `harness.php` (php:8.2). RCE-oob canary:
`${PCB_FLAG}` at `/flag/pcb_flag.txt` OUTSIDE the docroot — any sink-emitted PHP
is neutralized to the fixed reader
`echo @file_get_contents('/flag/pcb_flag.txt');`, so the flag surfaces only when
an mfunc tag survives into the executed cache file.

NVD (case.json `evidence.incomplete_fix_quote`): WP Super Cache before 1.3.2
"because of an incomplete fix for CVE-2013-2009". `patch_real.diff` is the 1.2 ->
1.3 delta adding `no_mfunc_in_comments` ("Remove mfunc, mclude and
dynamic-cached-content tags from comments"). The 1.3.2 fix zaps on the OPENING
tag alone ("Remove ending mfunc etc tags to mangle multi-comment tags").

- **V0 = 1.2** (`:39540` audited / `:39550` compose) — no guard: a single
  `<!--mfunc PAYLOAD-->x<!--/mfunc-->` comment becomes executable cache PHP ->
  flag echoed (repro.log: injected=true, served contains flag).
- **V1 = 1.3.1** (`:39541` / `:39551`, target) — the 2009 guard BLOCKS the
  single-comment seed (open+close in one comment -> zapped), but the split
  residual — comment #1 `<!--mfunc PAYLOAD-->` (opening only), comment #2
  `<!--/mfunc-->` (closing only) — survives per-comment filtering and recombines
  on the page -> `<?php PAYLOAD ;?>` in the cache file -> flag. Incomplete fix.
- **V2 = 1.3.2** (`:39542` / `:39552`, 2011 fix) — opening-tag-only zapping
  mangles comment #1 -> blocked (repro.log `_bypass_blocked_on_v2`).

- **Original trigger**: one guest comment carrying the complete
  `<!--mfunc echo @file_get_contents('/flag/pcb_flag.txt');-->x<!--/mfunc-->`
  (`poc/original_poc.py` candidate, `mode: "single_comment_mfunc"`).
- **Residual trigger**: TWO comments — `<!--mfunc <PAYLOAD>-->` then
  `<!--/mfunc-->` (`_heldout/bypass_poc.py` candidate, `mode:
"split_multi_comment"`).

Run: `python3 oracle.py --run-gate` (gate, flag
`PCBFLAG_3f18678ea9f252a815b751586a8548a9`: seed reaches@v0 / blocked@v1 /
residual reaches@v1 / residual blocked@v2; `_env_ready` all true; passed=true).
See `repro.log` and `case.json`.

> NOTE: the case mixes two build generations — `docker-compose.yml` +
> `wp-entrypoint.sh` + `scripts/verify.sh` define the CURRENT full-WordPress
> build (ports 39550-39552), while `Dockerfile` + `harness.php`, case.json
> `audit` (2026-07-16), the `base_url`s in `versions` (39540-39542) and the
> repro.log transcript record the earlier faithful-core php:8.2 harness run
> (`POST /harness.php`). The recorded gate booleans come from the harness run.
