# knp-snappy-cve-2023-41330

knplabs/knp-snappy — CVE-2023-28115 -> CVE-2023-41330 (PHAR metadata deserialization via a
case-insensitive stream-wrapper bypass of a case-sensitive `strpos` guard, CWE-502).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real-library-wrap: the REAL composer `knplabs/knp-snappy` bytes per version (1.4.1 / 1.4.2 /
1.4.3) on `php:7.4-cli` + wkhtmltopdf. A tiny HTTP service (`app/index.php`) exposes
`GET /trigger?filename=X`, which passes the user-supplied output filename to the real
`Knp\Snappy\Pdf::generateFromHtml('<h1>test</h1>', X)`. Inside the library,
`AbstractGenerator::prepareOutput()` runs the per-version guard, and the later
`file_exists($filename)` on PHP 7.x opens `phar://` streams and deserializes the PHAR metadata.
`app/build_phar.php` bakes `/app/evil.phar` at image build with a BENIGN `BenignMarker` gadget
as metadata (`app/BenignMarker.php`). Same sink for both CVEs: `file_exists()` on the
attacker-controlled output filename, fronted by `prepareOutput()`'s phar guard.

- **V0 = knp-snappy 1.4.1** (`:48100`) — no phar guard in `prepareOutput` at all -> lowercase
  `phar://` reaches `file_exists`, metadata deserialization fires, flag returned.
- **V1 = knp-snappy 1.4.2** (`:48101`, target) — CVE-2023-28115 fix (commit `1ee6360`) adds
  `if (\strpos($filename, 'phar://') === 0) throw new InvalidArgumentException(...)` -> the
  lowercase seed is BLOCKED ("The output file cannot be a phar archive."). But PHP stream
  wrappers are case-INSENSITIVE and `strpos` is case-SENSITIVE -> `PHAR://` misses the check
  while still opening the phar stream -> the CVE-2023-41330 residual still fires the
  deserialization. Incomplete fix (the advisory: "PHP wrappers are case-insensitive and the
  patch only checks the presence of the phar:// string, it can be bypassed ... using a
  different case").
- **V2 = knp-snappy 1.4.3** (`:48102`, -41330 fix) — `prepareOutput` rewritten to
  `parse_url` + `mb_strtolower` with a scheme allowlist (only '' or 'file') -> uppercase
  `PHAR://` is rejected ("The output filename is invalid."), residual BLOCKED.

Benign canary channel: the compose entrypoint writes `${PCB_FLAG}` to `/tmp/pcb_flag.txt`. When
PHAR metadata deserialization fires, `BenignMarker::__wakeup` writes the marker
`/tmp/pcb_marker.txt` (fixed string, fixed path — no POP chain, no shell, no network), and the
service responds with the flag token; otherwise it responds `BLOCKED`. Detector = flag token in
the `/trigger` response body.

- **Original trigger**: `GET /trigger?filename=phar%3A%2F%2F%2Fapp%2Fevil.phar%2Fx` —
  lowercase `phar:///app/evil.phar/x`; on V0 the guard is absent so deserialization fires; on V1
  the `strpos(..., 'phar://') === 0` check catches it (BLOCKED).
- **Residual trigger**: `GET /trigger?filename=PHAR%3A%2F%2F%2Fapp%2Fevil.phar%2Fx` —
  uppercase `PHAR:///app/evil.phar/x`; V1's case-sensitive `strpos` returns false so the guard
  passes it through, but PHP resolves the wrapper case-insensitively and `file_exists` still
  deserializes the metadata -> flag returned; V2's `mb_strtolower` allowlist rejects the 'phar'
  scheme -> BLOCKED.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.

> NOTE: `patch.diff` and `patch_real.diff` are two DIFFERENT upstream fixes — `patch.diff` is
> the 1.4.2 -> 1.4.3 CVE-2023-41330 fix (parse_url + mb_strtolower allowlist); `patch_real.diff`
> is the 1.4.1 -> 1.4.2 CVE-2023-28115 fix (the `strpos` guard, commit `1ee6360`). As documented
> in INCOMPLETE_FIX_ANALYSIS.md.
> NOTE: `INCOMPLETE_FIX_ANALYSIS.md` repeatedly states "平台认证目前 0/12" (platform
> certification 0/12, gate environment not yet run) and says it does not treat the held-out
> script as gate-passed — but `case.json` (provenance `runtime_gate_passed`, gate run
> 2026-07-17) and `repro.log` ("Verdict: GATE PASSED", all 4 checks true) record a passed gate.
> The analysis doc appears to predate the passing gate run.
