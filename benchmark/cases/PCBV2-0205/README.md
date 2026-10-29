# tomcat-cve-2021-25329

Apache Tomcat — CVE-2020-9484 -> CVE-2021-25329 (PersistentManager/FileStore session-pickle
deserialization via path-validation bypass; CWE not recorded in case.json, root_cause = deserialization).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Apache Tomcat Servlet container (official `tomcat:<tag>-jdk8-openjdk` images; the SUT is the real
`catalina.sh` — the Dockerfile only plants a `PersistentManager`+`FileStore` `context.xml`
(`directory="/usr/local/tomcat/sessions"`, `maxIdleBackup="1"`), a BENIGN classpath gadget, and
`marker.jsp`). `FileStore.file()` resolves the attacker-controlled `JSESSIONID` to
`<directory>/<id>.session` and, on an in-memory miss, `PersistentManager` deserializes that file with a
real `ObjectInputStream`. Same sink (`FileStore.file()` path check + session deserialization); the Tomcat
9 security page titles CVE-2021-25329 "Fix for CVE-2020-9484 was incomplete ... still vulnerable to
CVE-2020-9484."

- **V0 = Tomcat 9.0.34** (`:39480`; case.json/repro.log cite 9480) — `FileStore.file()` has NO path
  validation: `JSESSIONID=../../../../tmp/payload` canonicalizes to `/tmp/payload.session`, which is
  deserialized -> marker written.
- **V1 = Tomcat 9.0.35** (`:39481` / 9481, target) — CVE-2020-9484 fix (commit `3aa8f28d`) adds
  `!file.getCanonicalPath().startsWith(storageDir.getCanonicalPath())` -> the `../` traversal seed is
  BLOCKED — but it is a STRING-prefix check, so a sibling directory whose name is a string-prefix of the
  store dir (`sessions-extra` starts-with `sessions`) passes and still deserializes. Incomplete fix
  (CVE-2021-25329 open; fix commit `4785433a`).
- **V2 = Tomcat 9.0.43** (`:39482` / 9482, CVE-2021-25329 fix) — switches to
  `java.nio.file.Path.startsWith()`, which compares path COMPONENTS, so
  `sessions-extra` != `sessions` -> residual BLOCKED.

Canary channel: the entrypoint copies the build-time-serialized `BenignMarker` payload to
`/tmp/payload.session` AND `/usr/local/tomcat/sessions-extra/payload.session`; `BenignMarker.readObject()`
writes `${PCB_FLAG}` to `/tmp/pcb_marker.txt` upon deserialization (it is NOT a real gadget chain — only a
planted token write; a successful load surfaces as HTTP 500 `ClassCastException: BenignMarker cannot be
cast to java.lang.Long`), and `GET /marker.jsp` returns the token (`NO_MARKER` otherwise).

- **Original trigger**: `Cookie: JSESSIONID=../../../../tmp/payload` -> deserializes `/tmp/payload.session`;
  blocked on 9.0.35 (`WARNING fileStore.file Invalid persistence file`).
- **Residual trigger**: `Cookie: JSESSIONID=../sessions-extra/payload` -> canonical
  `/usr/local/tomcat/sessions-extra/payload.session` passes the 9.0.35 STRING check
  (`.../sessions-extra/...` starts with `.../sessions`), blocked on 9.0.43 by the component-wise
  `Path.startsWith()`.

Run: `PCB_FLAG=<flag> python3 oracle.py` (runs the 4-way Variant A gate). See `repro.log` and `case.json`.

> NOTE: port mismatch across the dossier. `docker-compose.yml` maps host ports `${PORT_V0_0:-39480}` /
> `${PORT_V1_0:-39481}` / `${PORT_V2_0:-39482}` -> 8080, while `case.json` versions list `port` 9480/9481/9482
> and `repro.log` ran against 9480/9481/9482; `oracle.py` hard-codes `PORTS = {"v0": 9480, "v1": 9481,
> "v2": 9482}` with a comment claiming it "matches docker-compose" — it does not match the compose file's
> defaults (the archived gate must have used PORT_* overrides).
