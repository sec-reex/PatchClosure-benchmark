# BUILD_TODO -- plexus-archiver-symlink-extraction-bypass  (DONE, gate_passed, REAL-APP-HTTP)

Rebuilt 2026-07-16 to comply with the HARD POLICY: the library must be triggered by an EXTERNAL HTTP
archive UPLOAD, not an in-process driver. NO rm -- old files overwritten in place; stale files left + reported.

- [x] Resolve V0/V1/V2 = plexus-archiver 3.5 / 3.6.0 / 4.8.0 (Maven Central, HTTP 200 verified).
- [x] Confirmed containment evolution (AbstractUnArchiver.extractFile): 3.5 no check; 3.6.0 canonical
      `.startsWith(dir)` check (CVE-2018-1002200); 4.8.0 `Files.isSymbolicLink` guard (CVE-2023-37460).
- [x] REAL Java HTTP upload service service/com/pcb/ExtractHttpService.java (com.sun.net.httpserver.HttpServer):
      POST /extract (raw tar body) -> temp file -> TarUnArchiver.setSourceFile/setDestDirectory/extract() ->
      check /work/out/flag (outside dest) -> return witness. GET /health readiness.
- [x] Faithful-core: pom.xml pulls org.codehaus.plexus:plexus-archiver:${PA_VER} (+deps); the service drives
      the REAL TarUnArchiver.extract(); no plexus code edited. Dockerfile COPYs service/ (not Driver.java).
- [x] docker-compose.yml profiles v0/v1/v2, ports 18990/18991/18992, ${PCB_FLAG:?}.
- [x] original_poc.py = CVE-2018-1002200 `../out/flag` seed tar (escapes V0, blocked V1) -- uploaded over HTTP.
- [x] _heldout/bypass_poc.py = CVE-2023-37460 dangling-symlink `entry1` residual tar (escapes V1, blocked V2).
- [x] oracle.py = HTTP-driven Variant A validate_case: POST /extract raw tar over real external HTTP.
- [x] Gate on real Docker: `python3 oracle.py --run-gate --with-v2` -> passed=true, residual_blocked_on_v2=true;
      all POST /extract returned http_status 200. See repro.log.
- [x] Teardown: down -v --rmi all + image prune -f; no images remain. Case dir = TEXT only.
- [x] case.json: run_mode=real-app-http, external_http_trigger=true, runs_real_software=true,
      is_verbatim_lift=false, stage=gate_passed + 3 booleans.

STALE (left in place per no-rm; referenced by nothing new): Driver.java (old in-process driver), __pycache__/.
