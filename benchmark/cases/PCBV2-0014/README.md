# xxe_phpspreadsheet_ucs4

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Incomplete-fix pair: **CVE-2019-12331 → CVE-2024-47873** (PHPOffice/PhpSpreadsheet, CWE-611 XXE).

One lineage-step later than the sibling `xxe_phpspreadsheet_utf7`. The `XmlScanner` charset guard —
`findCharSet()` / `toUtf8()` / the null-tolerant `<!DOCTYPE` scan — only anticipates ≤16-bit
encodings. A payload encoded in **UCS-4 / UTF-32** puts **three null bytes** between each ASCII char:
`findCharSet`'s `encoding="…"` regex can't read the declaration through the nulls (so no decode), and
the scan pattern `\0?` (at most one null) never matches the null-padded `<!DOCTYPE`. libxml then
auto-detects UTF-32 at parse time and resolves the external entity → XXE. CVE-2024-47873 (1.29.4)
strips nulls + BOM-detects in `findCharSet` and widens the scan `\0?`→`\0*`.

- **V0 = 1.7.0** on php:7.2.0 (pre-CVE-2019-12331): single decode, no double-encode re-check → the
  prior-form **double-UTF-7** original reads the flag.
- **V1 = 1.29.2** on php:8.2 (TARGET, incomplete): has the full CVE-2019-12331 lineage guard →
  double-UTF-7 blocked ("Suspicious Double-encoded XML"), **UCS-4/UTF-32 residual bypasses** it.
- **V2 = 1.29.4** on php:8.2 (complete fix, commit `31d7f7962e05`): UCS-4 blocked ("Detected use of
  ENTITY") and double-UTF-7 blocked ("UTF-7 encoding not permitted").

Sink: `src/PhpSpreadsheet/Reader/Security/XmlScanner.php :: findCharSet()/toUtf8()/scan()`, reached
via a **REAL PHP web app** — `POST /upload` (multipart) → `IOFactory::load()` (`www/index.php`).
Oracle: read-exfil (Variant A) — external entity `SYSTEM "file:///canary/flag.txt"` reflects the
per-run `${PCB_FLAG}` into cell A1, returned in the `/upload` HTTP response.

Distinctness vs `xxe_phpspreadsheet_utf7`: that residual is UTF-7 **double-encoding** (extra decode
layer); this residual is a **wider multibyte encoding class** (UCS-4/UTF-32 null-byte interleaving)
defeating the encoding-detection regex + the null-tolerant scan itself. Same XmlScanner sink.

## Run the gate
```
python3 oracle.py --run-gate --with-v2
```
Builds v0 (php:7.2.0) / v1,v2 (php:8.2) from `Dockerfile.web72` / `Dockerfile.web8` (composer:2.2-
resolved exact releases), plants the canary, serves the upload app, POSTs each crafted spreadsheet
over real HTTP, runs the differential, tears down (`down -v --rmi all`).
See `repro.log` for the raw gate evidence.

## Files
- `Dockerfile.web72`, `Dockerfile.web8`, `docker-compose.yml` — recipe (no vendored source/images);
  each service serves the web app via the PHP built-in server on a published port (v0 18790, v1
  18791, v2 18792).
- `www/index.php`, `www/router.php` — the REAL upload web app: `POST /upload` → `IOFactory::load()`
  of the uploaded spreadsheet → returns cell A1 in the HTTP response.
- `build_fixture.php` — packages the crafted `sheet1.xml` into a valid `.xlsx` (writer scaffold +
  swap); packaging only, NOT the sink.
- `original_poc.py` — [GIVEN] prior-form double-UTF-7 payload (CVE-2019-12331 residual form).
- `_heldout/bypass_poc.py` — [HELD-OUT] UCS-4/UTF-32 residual (CVE-2024-47873).
- `oracle.py`, `patch.diff`, `repro.log`, `case.json`.
- STALE (old in-process design, kept per NO-rm directive, unreferenced): `Driver.php`,
  `Dockerfile.php72`, `Dockerfile.php8`.
```
Why cross-PHP: the pair spans 2018–2024. V1→V2 (the incomplete-fix comparison) is SAME-PHP (8.2),
isolating exactly the 1.29.2→1.29.4 XmlScanner diff. V0 (7.2.0) only shows the original's provenance.
On PHP 8.x the scanner's `disableEntityLoaderCheck()` is a no-op, so with `LIBXML_NOENT|LIBXML_DTDLOAD`
the scanner regex is the sole guard — the faithful exploitable config for 1.29.x.
```
