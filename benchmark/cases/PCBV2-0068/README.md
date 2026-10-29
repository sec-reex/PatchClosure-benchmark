# apache-dolphinscheduler-cve-2024-23320

不完全修复分析：[INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)

Apache DolphinScheduler switch-task unsandboxed JavaScript evaluation -> code injection
(CWE-94 / CWE-20). Incomplete-fix pair **CVE-2023-49299 -> CVE-2024-23320**.

Faithful-core, recipe-only (no vendored jars/images). REAL Java HTTP service triggered by
an **EXTERNAL HTTP request**. The shared `Dockerfile` (multi-stage: a `curlimages/curl`
fetch stage + a `eclipse-temurin:11-jdk` runtime stage) pulls the PUBLISHED
`org.apache.dolphinscheduler:dolphinscheduler-master` (+ `-task-api`) at each version from
Maven Central and starts `Server.java` (`com.sun.net.httpserver`) on port 8080. A client
`POST /eval {condition,params}` over TCP; the service reflectively invokes the REAL,
unmodified `SwitchTaskUtils.generateContentWithTaskParams(...)` guard and `evaluate(...)`
Nashorn `engine.eval(...)` sink on the attacker input -- mirroring a real DS worker
evaluating a user-defined switch condition. No `docker compose exec`, no in-process driver.
Runtime `eclipse-temurin:11-jdk` (Nashorn "js" is JDK-builtin on Java 8/11; DolphinScheduler
3.1/3.2 target those). Host ports: V0 `:18318`, V1 `:18319`, V2 `:18321`.

- **V0 = 3.1.8** pre-CVE-2023-49299: `SwitchTaskUtils` has only `evaluate()` -> raw arbitrary-JS switch condition runs unsandboxed.
- **V1 = 3.1.9** (target) CVE-2023-49299 fix: added the empty-params + no-substitution guard, but only checks THAT a `${param}` substituted, not WHAT the content is.
- **V2 = 3.2.1** CVE-2024-23320 fix: added a keyword blacklist `{java,invoke,new,eval,function,import,\\}` on the substituted content.

Canary = benign `read-exfil` file read: `${PCB_FLAG}` planted at `/canary/flag.txt`; the
switch-condition JS reads it and surfaces `PCBOUT:<flag>` in the `POST /eval` response.
No real command is run -- only a benign file read.

Note: `Driver.java` is a STALE leftover from the previous (banned) in-process design and is
no longer referenced by any recipe file; `Server.java` supersedes it.

Gate (real Docker): `python3 oracle.py --run-gate --with-v2` ->
`original@v0 reaches`, `original@v1 blocked`, `bypass@v1 reaches`, `residual@v2 blocked` = all true.
See `repro.log`. Teardown: `PCB_FLAG=teardown docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`.
