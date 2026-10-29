# pivotal-spring-integration-zip-cve-2018-1263

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Pivotal spring-integration-zip — CVE-2018-1261 -> CVE-2018-1263 (Zip-Slip path traversal / arbitrary file write, CWE-22).

**Run mode: real-app-http.** A REAL Java HTTP service (`service/com/pcb/UnzipHttpService.java`,
`com.sun.net.httpserver.HttpServer`) unzips an EXTERNALLY-uploaded archive via the REAL, unmodified
spring-integration-zip `UnZipTransformer.transform()`:

- `POST /unzip?mode=file`  -> `ZipResultType.FILE`      (framework writes each entry; CVE-2018-1261 channel)
- `POST /unzip?mode=bytes` -> `ZipResultType.BYTE_ARRAY` (framework returns the errant name; CVE-2018-1263 channel)

Escape witness = `/work/out/flag` OUTSIDE the extraction root `/work/dest`. The same malicious entry
`../../out/flag` exercises both branches. V0=1.0.0.RELEASE, V1=1.0.1.RELEASE (target, incomplete fix),
V2=1.0.2.RELEASE.

Run: `PCB_FLAG=teardown python3 oracle.py --run-gate --with-v2`

Stale leftovers (superseded by the HTTP service; kept per NO-rm policy, unreferenced): `Driver.java`, `driver.py`.

See BUILD_TODO.md, repro.log and ../SPEC.md.
