# jackson-databind-cve-2018-5968

jackson-databind — CVE-2017-7525 -> CVE-2018-5968 (polymorphic/default-typing deserialization, CWE-502 + CWE-184). **gate_passed** (Variant A, **real-app-http**).

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

**Trigger = REAL external HTTP.** Per profile a REAL small Java HTTP REST service (`com.pcb.DeserHttpService`, JDK built-in `com.sun.net.httpserver.HttpServer`) boots with the REAL, unmodified published `jackson-databind:{2.8.8,2.8.11,2.8.11.1}` on its classpath and exposes `POST /deser` (application/json): the raw JSON body is deserialized via `om.enableDefaultTyping(); om.readValue(body, Object.class)`. The oracle POSTs the benign default-typing body `["<FQCN>", {}]` to `http://127.0.0.1:{18780,18781,18782}/deser`; the service echoes `PCB_CANARY_FLAG=<token>` iff the version's blacklist let the class NAME through and a benign shadow bean was instantiated. (Supersedes the earlier banned in-process `docker compose exec` Driver.java harness.)

Same original CVE (CVE-2017-7525) as `jackson-databind-cve-2017-15095` and `jackson-databind-cve-2017-17485`, but a **distinct** residual/bypass and version window:

| | -15095 | -17485 | -5968 (this case) |
|---|---|---|---|
| residual class | `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` | `org.springframework.context.support.FileSystemXmlApplicationContext` | `org.hibernate.jmx.StatisticsService` + `org.apache.ibatis.datasource.jndi.JndiDataSourceFactory` |
| window (V0/V1/V2) | 2.8.8 / 2.8.9 / 2.8.10 | 2.8.8 / 2.9.3 / 2.9.4 | 2.8.8 / **2.8.11** / **2.8.11.1** |
| fix commit | databind#1680+#1737 | databind#1855 | **databind#1899** |
| fix mechanism | add exact FQCN to blacklist set | Spring `AbstractApplicationContext` superclass-name walk | **add two exact FQCNs (Hibernate/iBatis) to blacklist set** |

- **V0 2.8.8** — pre-blacklist (`SubTypeValidator` is `@since 2.8.11`); the seed `InvokerTransformer` name instantiates -> flag read.
- **V1 2.8.11** (GIVEN, target) — `SubTypeValidator.validateSubType()` exact-name set (the -7525 + -15095 + -17485 gadgets) plus the Spring superclass walk blocks the seed, but does NOT enumerate the Hibernate JMX / iBatis JNDI gadget names (and they are not `org.springframework.`, and 2.8.11 has no `com.mchange.v2.c3p0.` prefix rule) -> the residuals still deserialize.
- **V2 2.8.11.1** (negative) — `#1899` adds `org.hibernate.jmx.StatisticsService` and `org.apache.ibatis.datasource.jndi.JndiDataSourceFactory` to the exact-name set -> residuals blocked.

Note the residual is closed here by the SAME mechanism as -15095 (add exact FQCN) but a DIFFERENT class family and a DIFFERENT release branch (2.8.11 -> 2.8.11.1, the micro-release that is *exactly* the CVE-2018-5968 fix), and V1=2.8.11 already contains the -15095 AND -17485 blacklists, so the only residual open on this V1 is the -5968 one.

Canary = benign shadow classes (real gadget libs — hibernate-core, mybatis, commons-collections — NOT on classpath); each leaf reads `${PCB_FLAG}` from `/canary/flag.txt` in its no-arg constructor, which runs only when the version's guard permits the name. No gadget chain, no JNDI lookup, no remote fetch, no exec.

Run the gate: `python3 oracle.py --run-gate --with-v2`. See `repro.log` for the recorded run.
