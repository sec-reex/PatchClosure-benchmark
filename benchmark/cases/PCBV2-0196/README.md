# spring-framework-cve-2022-22965

Spring Framework — CVE-2010-1622 → CVE-2022-22965 (Spring4Shell: data-binding/mass-assignment
blocklist bypassed via the JDK9+ `class.module.classLoader` hop, CWE-915).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (repro.log: V0 original
marker 200 + flag; V1 original binding 200 but marker 404 = BLOCKED; V1 bypass marker 200 + flag =
REACHES; V2 bypass marker 404 = BLOCKED; `[2026-08-02 real gate] clean rebuild -> --gate
passed=True ... UPGRADED to strict_gold`).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Spring: a minimal Spring MVC WAR (`app/src`, `pcb.HelloController` `@RequestMapping("/hello")`
binding a `Greeting` POJO from request params) is built at Docker build time from REAL spring-web
JARs pulled from Maven Central (`-Dspring.version=${SPRING_VER}`) and deployed as
`webapps/ROOT.war` on pinned pre-mitigation Tomcat (V0: JDK8/Tomcat 8.5.77; V1/V2:
JDK17/Tomcat 9.0.60 — Tomcat 9.0.62+/8.5.78+ carry their own Spring4Shell mitigation, so the
differential isolates the Spring fix). The vulnerable sink is REAL Spring data binding
(`CachedIntrospectionResults`), which traverses `Object.getClass()` descendants for nested
property paths. WAR packaging is required — the AccessLogValve pipeline path exists only for
WAR-deployed apps. The advisory: CVE-2022-22965 "bypasses the patch for CVE-2010-1622 via the
JDK9+ java.lang.Module classLoader path".

- **V0 = Spring 3.0.2.RELEASE** (`:39650`) — no CVE-2010-1622 blocklist -> `class.classLoader.*`
  binding reachable -> original writes its marker file (200 + flag).
- **V1 = Spring 5.3.17** (`:39651`, target) — CVE-2010-1622 fix (3a5af35d, SPR-7227) makes
  `CachedIntrospectionResults` skip the `classLoader` descriptor `if
  Class.class.equals(beanClass)` -> the direct `class.classLoader` seed is BLOCKED (binding
  request still 200 but the property is silently skipped; marker 404). The check is by property
  NAME on `java.lang.Class` only; on JDK9+ `Class.getModule()` exposes
  `class.module.classLoader`, whose `getClassLoader()` returns the SAME webapp ClassLoader ->
  residual writes the flag. Incomplete fix: a JDK9+ hop around a name-based blocklist.
- **V2 = Spring 5.3.18** (`:39652`, -22965 fix) — stricter type filtering blocks
  `class.module.*` traversal -> residual BLOCKED (binding 200, marker 404).

Benign canary channel: NO webshell, no JSP, no code execution. The GET params reconfigure Tomcat's
`AccessLogValve` (`pattern=<PCB_FLAG>`, `suffix=.txt`, `directory=webapps/ROOT`,
`prefix=pcb_original`/`pcb_bypass`, `fileDateFormat=`) so the valve writes a plain marker file into
the served webapp dir; detection = flag token in `GET /pcb_bypass.txt` (or `/pcb_original.txt`)
served by Tomcat's DefaultServlet.

- **Original trigger**: `GET /hello?class.classLoader.resources.context.parent.pipeline.first.pattern=<FLAG>&...suffix=.txt&directory=webapps/ROOT&prefix=pcb_original&fileDateFormat=&buffered=false`
  (CVE-2010-1622 path; the 2010 blocklist filters it on V1).
- **Residual trigger**: same valve params via
  `class.module.classLoader.resources.context.parent.pipeline.first.*` — `java.lang.Class.getModule()`
  (JDK9+) → `Module.getClassLoader()` returns the webapp ClassLoader, bypassing the 2010
  name-based blocklist (CVE-2022-22965 / Spring4Shell).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE: case.json's audit (2026-07-16) records an earlier `oracle --run-gate` result of
> `passed=false` attributed to a harness timing bug (the AccessLogValve write is buffered and
> landed after the oracle's 1s window), explicitly "NOT a non-repro"; `status.frozen_2026-08-02`
> records the superseding clean-rebuild gate with `passed=True` and bypass@V2 404 + no marker file.
