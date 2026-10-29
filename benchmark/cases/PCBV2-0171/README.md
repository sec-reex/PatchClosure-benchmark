# phpspreadsheet-phar-wrapper-parseurl-bypass

PhpSpreadsheet — CVE-2026-34084 -> CVE-2026-45034 (phar:// stream-wrapper LFI via `parse_url` guard
bypass; case.json gives `mechanism_family: file-wrapper-lfi`, root cause
"Improper_Neutralization_of_Special_Elements_stream_wrapper_LFI", no CWE code).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (repro.log: "VERDICT: GATE
PASSED (genuine, real-service-http)").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL PHP HTTP service (`php:8.2-apache` + mod_php, `app.php` at the document root) installs the REAL
composer/Packagist `phpoffice/phpspreadsheet` at `PS_VER` and serves `POST /` with form field
`path=<url>`. `app.php` hands the path UNMODIFIED to `Reader\Csv::load($path)` ->
`BaseReader::openFile` -> `File::assertFile` -> `File::prohibitWrappers` — the genuine guard being
studied; nothing in PhpSpreadsheet is modified. Same sink, same guard hardened across the three
versions; the bypass is exactly the advisory's own observation that `parse_url` is "not equivalent to
'does the path contain a wrapper'".

- **V0 = 1.30.2** (`:38080`) — `File::prohibitWrappers()` does NOT exist -> any `phar://` path
  loads -> seed reaches the canary. (pre-CVE-2026-34084)
- **V1 = 1.30.3** (`:38081`, target) — CVE-2026-34084 fix adds `prohibitWrappers()`: it calls
  `parse_url($filename, PHP_URL_SCHEME)` and throws
  `"Stream wrappers are not permitted as file paths"` when `is_string($scheme) && strlen($scheme) > 1`
  -> the two-slash seed is BLOCKED, but the three-slash form makes `parse_url` return `false`
  (`is_string` false, no throw) while PHP's stream layer still honours the wrapper -> the
  CVE-2026-45034 residual still reaches the canary. Incomplete fix.
- **V2 = 1.30.5** (`:38082`, CVE-2026-45034 fix) — `parse_url` is replaced by
  `Preg::isMatch('~^phar://~i', $filename)` (+ ctrl-char and nested-wrapper regexes) -> BOTH forms
  throw `"Disallowed stream wrapper"`.

Benign read-exfil channel: at container start the compose command runs `build_phar.php`
(`phar.readonly=0`), which builds `/work/flag.phar` — a benign phar whose single CSV member
`sheet.csv` carries the per-run `${PCB_FLAG}` in cell A1 (OUTSIDE the app dir, from the environment,
never in app code). A normal (non-wrapper) load cannot reach it. SUCCESS = the flag token appears in
the HTTP JSON response `surfaced` field, i.e. the wrapper reached the loader. PHP 8.2 base => benign
file-READ primitive only; no phar metadata deserialization, no gadget, no command execution.

- **Original benign trigger**: `phar://work/flag.phar/sheet.csv` (canonical two-slash form;
  `parse_url(..., PHP_URL_SCHEME)` => `'phar'` — the advisory's `phar://x/dummy.csv` example that
  "returns the string 'phar' and the throw fires correctly").
- **Residual benign trigger**: `phar:///work/flag.phar/sheet.csv` (three slashes -> absolute archive
  path; `parse_url` => `false`, guard skipped, stream layer still opens the wrapper).

Gate (repro.log, FLAG=`PCBFLAG_...`): original REACHES on v0 (`surfaced="PCBFLAG_...|benign-..."),
BLOCKED on v1 with "Stream wrappers are not permitted as file paths"; bypass REACHES on v1 (flag
surfaced = residual); v2 (1.30.5) throws "Disallowed stream wrapper" for BOTH forms.

Run: `python3 oracle.py --run-gate` (also `--probe orig|bypass --version v0|v1|v2`). See `repro.log`
and `case.json`.

> NOTE: `repro.log`'s "STALE LEFTOVERS" section claims `harness.php` (retired in-process
> `docker compose exec` shortcut) is "left in dir, NOT referenced by compose/oracle/case.json", but
> `harness.php` is NOT present in the case directory (verified via `ls -la`) — only the
> `__pycache__/` and `_heldout/__pycache__/` leftovers listed there actually exist.

> NOTE: `case.yaml` says `run_mode: real-app-http` and `exposed_ports: [80]` /
> `readiness: http://127.0.0.1:80/`, while `case.json` says `run_mode: "real-service-http"` and
> `docker-compose.yml` actually maps host ports 38080/38081/38082 -> container port 80. The compose
> mapping is what the gate run used (repro.log probe detail cites @38080/@38081/@38082).
