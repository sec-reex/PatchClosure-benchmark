# typo3-cve-2013-4321

TYPO3 — CVE-2013-4250 -> CVE-2013-4321 (the SA-2013-002 fix checks the RAW rename
target against `fileDenyPattern`, but `GeneralUtility::verifyFilenameAgainstDenyPattern`
only rejects `[[:cntrl:]]` chars and the anchored regex `\.(php[3-6]?|phpsh|phtml)(\..*)?$`
doesn't match a TRAILING SPACE — which `LocalDriver::sanitizeFileName`'s `trim()`
then strips AFTER the check, so `<x>.php ` lands on disk as `.php` and executes;
arbitrary PHP code execution via file-rename extension-filter bypass, CWE-434 /
CWE-94). **Genuine incomplete fix; gate passed on real Docker (Variant A).**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

The REAL upstream TYPO3 6.0 core (`git clone --branch TYPO3_6-0-4 / -6-0-8 / -6-0-9`
of the ENTIRE TYPO3/typo3 repo into the Apache docroot; `harness.php` autoloads
the in-tree `typo3/sysext/core/Classes`) on php:7.4-apache. `harness.php` invokes
the version's actual `ResourceStorage::renameFile` decision verbatim via
reflection (`checkFileExtensionPermission` + `LocalDriver::sanitizeFileName` +
`verifyFilenameAgainstDenyPattern` — no security logic reimplemented); the
physical rename + mod_php execution are real. (A full TYPO3 6.0 backend install
was intentionally avoided as unautomatable, per provenance.) RCE canary:
`${PCB_FLAG}` at `/flag/pcb_flag.txt` OUTSIDE the docroot — only an executed
renamed `.php` echoes it; the client controls only the rename string.

TYPO3-CORE-SA-2013-003 (case.json `evidence.incomplete_fix_quote`): "The check
for denied file extensions implemented in the File Abstraction Layer as mentioned
in advisory TYPO3-CORE-SA-2013-002 was incomplete. It was still possible for
editors to rename files to have denied file extensions by inserting special
characters that were removed at a later point." `patch_real.diff` is the
CVE-2013-4250 fix (commit `2ab93c754c60bad61a2da23cb783b8885884ecc7`):
`checkFileExtensionPermission($targetFileName)` added to `renameFile`/`createFile`.
The 6.0.9 fix sanitises (trims) BEFORE the deny check.

- **V0 = 6.0.4** (`:39470`) — `renameFile` has NO extension check: direct rename
  to `seed_shell.php` -> executes -> flag (repro.log: `[EXEC]`).
- **V1 = 6.0.8** (`:39471`, target) — the 4250 fix BLOCKS the direct seed
  (`IllegalFileExtensionException`), but `residual_shell.php ` (one trailing
  space) passes the RAW check, `trim()` strips the space, the file lands as
  `residual_shell.php` -> executes -> flag. Incomplete fix.
- **V2 = 6.0.9** (`:39472`, 4321 fix) — trim-before-check normalises to `.php` ->
  both residual and seed blocked (repro.log negative control).

- **Original trigger**: rename target `seed_shell.php` (plain denied extension;
  `poc/original_poc.py` candidate, `mode: "direct_php_rename"`).
- **Residual trigger**: rename target `residual_shell.php ` (ONE trailing space;
  `_heldout/bypass_poc.py` candidate, `mode: "trailing_space_bypass"`).

Run: `python3 oracle.py --gate` (gate 2026-07-11: seed executes@v0 / blocked@v1 /
bypass executes@v1 / bypass blocked@v2; passed=true). See `repro.log` and
`case.json`.
