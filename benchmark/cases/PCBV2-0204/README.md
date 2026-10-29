# suitecrm-cve-2026-29103

SuiteCRM — CVE-2024-49774 -> CVE-2026-29103 (Module Loader `ModuleScanner` blacklist bypass via token
parsing -> install-time PHP execution, CWE not recorded in case.json; mechanism_family =
`blacklist_bypass_token_parsing`, root_cause = command-injection).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL SuiteCRM (full app from `salesagility/SuiteCRM` git tags on php:8.1-apache + MySQL 8.0) exposes the
admin Module Loader: login -> `POST /index.php?module=Administration&view=module&action=UpgradeWizard&run=upload`
(MLP zip) -> AJAX `HandleAjaxCall`/`performInstall`. `ModuleScanner::scanFile` tokenizes the package's PHP
with `token_get_all` and blacklists dangerous function names; only a clean scan reaches
`ModuleInstaller::install()`, which `include`s the manifest's `post_execute` script as real PHP. Same sink
(same `scanFile` blacklist, same install-time include); GHSA-5jjq-9qch-9rg7 calls CVE-2026-29103 "a direct
Patch Bypass of CVE-2024-49774."

- **V0 = SuiteCRM v7.14.5** (`:39140`) — the scanner compares only `T_STRING` tokens against the blacklist,
  so a quoted callable `'file_get_contents'(...)` (a `T_CONSTANT_ENCAPSED_STRING`, not `T_STRING`) passes ->
  install runs the post_execute script.
- **V1 = SuiteCRM v7.15.0** (`:39141`, target) — CVE-2024-49774 fix (first landed 7.14.6; `patch_real.diff`)
  adds `case T_CONSTANT_ENCAPSED_STRING:` with `trim(strtolower($token[1]),'\'"')` so the quoted seed hits
  the blacklist and `(` records `ML_INVALID_FUNCTION` -> BLOCKED. But ANY single-character token (`=`, `.`,
  `;` — returned as plain strings by `token_get_all`) resets `$checkFunction = false`, so a CONCATENATED
  name `('file_get'.'_contents')(...)` scans clean while install-time PHP still executes the joined
  callable. Incomplete fix.
- **V2 = SuiteCRM v7.15.1** (`:39142`, CVE-2026-29103 fix) — the token loop is replaced by `nikic/php-parser`
  AST analysis (`scanFileAST` / `ModuleScannerVisitor`); the concatenated call is recognized as a
  `FuncCall` of a blacklisted function -> residual BLOCKED (see NOTE below on V2 evidence).

Canary channel: the entrypoint plants `${PCB_FLAG}` at `/tmp/pcb_canary.txt` (outside app code). The
uploaded package's `post_execute` script reads that file and writes it to web-root
`/var/www/html/pcb_marker_{original,bypass}.txt` — the flag appears in the HTTP body of
`GET /pcb_marker_*.txt` IFF the scanner passed the package AND `post_execute` executed. Benign framing:
the "RCE" only reads the planted canary file.

- **Original trigger**: `PCBOriginal` MLP whose post_execute runs
  `'file_get_contents'('/tmp/pcb_canary.txt')` (quoted-string callable; blocked on 7.15.0 via the
  `T_CONSTANT_ENCAPSED_STRING` case).
- **Residual trigger**: `PCBBypass` MLP (`_heldout/bypass_module.zip`) whose post_execute runs
  `('file_get'.'_contents')('/tmp/pcb_canary.txt')` — the `.` single-character token resets
  `$checkFunction`, so 7.15.0 scans clean and install-time PHP executes the concatenated name.

Run: `PCB_FLAG=<flag> python3 oracle.py --run-gate`. See `repro.log` and `case.json`.

> NOTE: case.json claims `oracle.checks.residual_v2_blocked: true` and its audit evidence describes V2
> (v7.15.1) closing the residual, but the actual artifacts show only three checks: `oracle.py` runs
> original@v0, original@v1, bypass@v1 (its docstring: "Variant A gate: original reaches flag on V0,
> blocked on V1, bypass reaches flag on V1"), and `repro.log` (2026-07-17) records exactly those three
> results (original@v0 = flag, original@v1 = BLOCKED_BY_SCANNER, bypass@v1 = flag) with NO v2 run. The
> v2-closure assertion is therefore not backed by the archived gate log.
