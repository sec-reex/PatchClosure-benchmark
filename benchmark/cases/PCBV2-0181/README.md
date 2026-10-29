# qdpm-cve-2020-7246

qdPM — CVE-2015-3884 -> CVE-2020-7246 (the 2015 mitigation is the shipped
`uploads/**/.htaccess` script-block (`<FilesMatch \.(php...)> Deny from all`);
qdPM 9.1's myAccount delete-photo branch still runs an unguarded
`unlink(sf_upload_dir.'/users/'.photo_preview)`, so a path-traversal
`photo_preview='../.htaccess'` DELETES the protection and the uploaded PHP shell
executes; path traversal + arbitrary file upload -> RCE, CWE-22 / CWE-434).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real qdPM (Symfony 1.4 PHP) from the official SourceForge release zips
(`qdPM_9.1.zip` / `qdPM_9.2.zip`, fetched at build time) on
`php:7.4-apache` + `mariadb:10.11`, installed via qdPM's OWN HTTP installer;
driven as an ordinary seeded member (md5 login, CSRF tokens scraped when
rendered). RCE canary: `${PCB_FLAG}` planted at `/flag/pcb_flag.txt` OUTSIDE the
docroot — only an executed uploaded PHP shell (`<?php echo
file_get_contents("/flag/pcb_flag.txt");?>`) echoes it.

NVD on CVE-2020-7246 (case.json `evidence.incomplete_fix_quote`): "An attacker
can upload a malicious PHP code file via the profile photo functionality,
leveraging a path traversal vulnerability in the users['photop_preview'] delete
photo feature to bypass .htaccess protection. This issue exists because of an
incomplete fix for CVE-2015-3884." `patch_real.diff` documents the official
CVE-2015-3884 mitigation (the two `uploads/**/.htaccess` FilesMatch blocks); its
header notes there is NO 8.x->9.1 upstream delta — the zips already ship them.
The 9.2 fix (CVE-2020-7246) wraps the upload move, the photo_preview reuse AND
the unlink in the NEW `app::is_image()` (`mime_content_type`).

V0 construction (documented in provenance): identical 9.1 app code with the
shipped `uploads/**/.htaccess` script-blocks neutralised at boot
(`STRIP_UPLOAD_HTACCESS=1`) to model the pre-3884-mitigation state; no business
code modified.

- **V0 = qdPM 9.1, .htaccess stripped** (`:39450`) — the seed's photo upload
  (`pcb_seed.php`) lands in `uploads/users/` and a direct GET EXECUTES it ->
  canary (repro.log: HTTP 200 CANARY-HIT).
- **V1 = qdPM 9.1 stock** (`:39451`, target) — the 3884 mitigation BLOCKS the
  seed (direct GET 403, nothing executes), but the residual uploads
  `pcb_bypass.php` then submits TWO myAccount updates with
  `remove_photo=1&photo_preview='.htaccess'` and `'../.htaccess'` ->
  `unlink(uploads/users/.htaccess)` + `unlink(uploads/.htaccess)` -> shell
  executes -> flag. Incomplete fix.
- **V2 = qdPM 9.2** (`:39452`, 7246 fix) — `app::is_image()` blocks both: the
  `.php` never lands and the `.htaccess` files are never unlinked (both remain
  266 bytes; repro.log / audit).

- **Original trigger**: upload `users[photo]=(pcb_seed.php, <?php ... ?>)` via
  `myAccount/update`, then `GET /uploads/users/<rand-pcb_seed.php>`
  (`poc/original_poc.py` candidate, `mode: "direct"`).
- **Residual trigger**: same upload of `pcb_bypass.php`, then
  `myAccount/update` with `remove_photo=1` and
  `users[photo_preview]` = `.htaccess` then `../.htaccess`, then
  `GET /uploads/users/<rand-pcb_bypass.php>` (`_heldout/bypass_poc.py`
  candidate, `mode: "htaccess_bypass"`, `traversals`).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-10, flag
`PCBFLAG_59dd66b5baeafc806834885453b701ae`: seed reaches@v0 / blocked@v1 /
residual reaches@v1; passed=true; V2 separately verified blocked). See
`repro.log` and `case.json`.

> NOTE (build env, from case.json `audit`/Dockerfile): Docker's build network
> blackholes SourceForge (resolves into reserved 198.18/15), so the gate
> pre-fetches the release zips on the host into the build context; the zips are
> not committed (removed at teardown) and only text stays in the case dir.
> Fix (2026-10-11, task PCBV2-0181): `poc/seed_exec.py` `run_probe` now also
> recognises `mode="htaccess_bypass"` — the mode declared by
> `poc/bypass_poc.py` / `_heldout/bypass_poc.py` — with the same semantics as
> `oracle.py` `run_probe` (upload the .php photo, then drive the delete-photo
> branch with `photo_preview`=<each `traversals` entry to unlink
> `uploads/**/.htaccess`, then GET `/uploads/users/<f>` so the shell executes);
> the legacy `"htaccess_X"` literal embedded in `scripts/verify.sh` is still
> accepted, so verify.sh is unchanged.
