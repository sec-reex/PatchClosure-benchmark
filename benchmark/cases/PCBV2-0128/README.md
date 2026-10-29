# jackson-databind-cve-2017-15095

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

jackson-databind — CVE-2017-7525 -> CVE-2017-15095 (Deserialization, CWE-502 + CWE-184). Genuine incomplete fix.
**REAL jackson-databind behind a REAL Java HTTP REST service; deserialization triggered by an EXTERNAL HTTP request.**

**Mechanism.** With default typing enabled, JSON `["<class>", {..}]` makes `ObjectMapper.readValue()` resolve and
instantiate the attacker-named class. CVE-2017-7525 (databind#1599, fixed in 2.8.9) added a class-name BLACKLIST
— `BeanDeserializerFactory.checkIllegalTypes()` / `DEFAULT_NO_DESER_CLASS_NAMES`. The blacklist is *enumerated*
(default-allow), so it was INCOMPLETE: CVE-2017-15095 (databind#1680+#1737, fixed in 2.8.10 per NVD "before
2.8.10") extends the same set with more gadget class names incl. the c3p0 family.

**Real HTTP REST service (the web-real trigger).** A small `com.pcb.DeserHttpService` (JDK built-in
`com.sun.net.httpserver.HttpServer`, `maven:3.9-eclipse-temurin-8`) boots per profile with the REAL, unmodified
Maven-Central `jackson-databind:${JACKSON_VER}` (+ transitive jackson-core/jackson-annotations) on its classpath
and exposes `POST /deser` (application/json): `om.enableDefaultTyping(); om.readValue(requestBody, Object.class)`
— the real polymorphic deser of an attacker JSON body. jackson-databind itself is never modified.

**Versions (recipe-only — Maven Central at build time, no vendored jars):**
- V0 = `jackson-databind:2.8.8` — pre-CVE-2017-7525, NO blacklist (host port 18760).
- V1 = `jackson-databind:2.8.9` — CVE-2017-7525 fix (#1599 blacklist), TARGET, incomplete (18761).
- V2 = `jackson-databind:2.8.10` — CVE-2017-15095 fix (#1680+#1737 extended blacklist) (18762).

**Benign shadow-class canary (NO gadget).** The blacklist matches by class name, so two benign empty
`Serializable` beans occupy the exact blacklisted FQCNs (`org.apache.commons.collections.functors.InvokerTransformer`
= original; `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` = residual, a #1737 name added only in 2.8.10).
The real gadget libraries are NOT on the classpath, so jackson's name-based decision governs. Each bean's no-arg
CONSTRUCTOR reads `${PCB_FLAG}` from `/canary/flag.txt` and stashes it in `com.pcb.CanaryHolder`; the HTTP service
echoes the token in the response only when the version's blacklist PERMITS the name and jackson instantiates the
bean. No gadget chain, no JNDI, no command execution.

**Gate (Variant A) — verified on real Docker over external HTTP (`python3 oracle.py --run-gate --with-v2`):**
- original(InvokerTransformer) POST /deser @V0 → REACHES; @V1 → BLOCKED ("Illegal type ... prevented for security reasons").
- residual(WrapperConnectionPoolDataSource) POST /deser @V1 → REACHES; @V2 → BLOCKED.
- `passed=true`, `_residual_blocked_on_v2=true`, `_original_blocked_on_v2=true`.

See `case.json`, `patch.diff`, `repro.log`, and `../SPEC.md`. `_heldout/` is never exposed to the SUT.
