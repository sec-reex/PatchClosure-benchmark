# hl7-fhir-org-hl7-fhir-core-cve-2023-28465

HL7 FHIR (org.hl7.fhir.core) — CVE-2023-24057 -> CVE-2023-28465 (Zip-Slip guard
normalized the path but kept a String `startsWith(targetDir)` prefix check, so a
sibling dir sharing the basename prefix passes; CWE-22). **Genuine incomplete
fix; gate passed on real Docker over EXTERNAL HTTP.**

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Java HTTP upload service (`Server.java`, `com.sun.net.httpserver.HttpServer`)
accepts `POST /unzip` (raw `application/zip` body) and hands the bytes to the
REAL, unmodified published Maven artifact
`ca.uhn.hapi.fhir:org.hl7.fhir.r4b:<ver>` — the sink is the library's own
`org.hl7.fhir.r4b.terminologies.TerminologyCacheManager.unzip(is, targetDir)`
into a fresh per-request extraction root `<base>/cache/tx-cache`. State-write
(zip-slip) canary: the uploaded archive's escaping ENTRY NAME performs the
traversal and its CONTENT is the per-run `${PCB_FLAG}`; the service returns
`escaped_files` (files landing OUTSIDE the extraction root) and the flag appears
in an escaped file's content iff the escape succeeded. The flag never lives in
Server.java, env, or org.hl7.fhir source.

`patch_real.diff` is the CVE-2023-24057 upstream fix (commit
`b50aec59124416b7315a49220cfc3999223414cc`, 5.6.90 -> 5.6.92): the entry path is
normalized to an absolute string
(`Path.of(Utilities.path(targetDir, ze.getName())).normalize().toFile().
getAbsolutePath()`) before the guard. Incomplete — the guard is still
`path.startsWith(targetDir)`, a STRING prefix check on a non-slash-terminated
path, so `"/usr/outnot".startsWith("/usr/out")` (the advisory's own example,
case.json `evidence.incomplete_fix_quote`). The 5.6.106 fix (CVE-2023-28465)
switches to component-wise `Path.startsWith(Path.of(targetDir).normalize())`.

- **V0 = 5.6.90** (`maven:org.hl7.fhir.r4b:5.6.90`, `:18690`) — no normalize,
  plain string prefix guard: mid-`..` entry keeps the `targetDir` prefix yet the
  FS resolves it outside -> escape (repro.log: escaped `pwned/escaped.txt` with
  the flag).
- **V1 = 5.6.92** (`maven:org.hl7.fhir.r4b:5.6.92`, `:18692`, target) — the
  24057 fix BLOCKS the mid-`..` seed (`RuntimeException: Entry with an illegal
  path`), but the sibling entry `../tx-cache-esc/escaped.txt` yields
  `<base>/cache/tx-cache-esc/...` which string-startsWith
  `<base>/cache/tx-cache` -> guard passes -> escape, flag in
  `cache/tx-cache-esc/escaped.txt`. Incomplete fix.
- **V2 = 5.6.106** (`maven:org.hl7.fhir.r4b:5.6.106`, `:18706`, 28465 fix) —
  component-wise `Path#startsWith`: `"tx-cache-esc" != "tx-cache"` ->
  RuntimeException, blocked.

- **Original trigger**: zip entries `["x/", ""]` +
  `["x/../../../pwned/escaped.txt", FLAG]` (mid-`..` escape;
  `poc/original_poc.py` `entries()`).
- **Residual trigger**: single entry `["../tx-cache-esc/escaped.txt", FLAG]`
  (sibling partial-path; `_heldout/bypass_poc.py` `entries()`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-16, flag `PCBFLAG_208be863fc5190bece92c2058f326e0f`: reach@v0 /
blocked@v1 / bypass reach@v1 / residual blocked@v2; passed=true; independently
re-confirmed with raw `curl -X POST --data-binary @zip` to `:18692`).

> NOTE: `Server.java` and `pom.xml` sit in the case root (referenced by the
> Dockerfile). A prior in-process `Driver.java` design was replaced by the
> real-HTTP-service rebuild on 2026-07-16 (see repro.log "WHAT CHANGED"); the
> stub-era note about a Driver no longer applies.
