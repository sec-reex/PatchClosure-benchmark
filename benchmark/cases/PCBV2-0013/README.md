# jackson-databind-cve-2017-17485

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

jackson-databind — CVE-2017-7525 -> CVE-2017-17485 (polymorphic/default-typing deserialization, CWE-502). **gate_passed** (Variant A). **run_mode = real-app-http**: the REAL, unmodified published jackson-databind runs inside a REAL small Java HTTP REST service (`com.pcb.DeserHttpService`, JDK built-in `com.sun.net.httpserver.HttpServer`) that exposes `POST /deser`; the deserialization is triggered by an **EXTERNAL HTTP request** whose JSON body `["<FQCN>", {}]` is fed to `om.enableDefaultTyping(); om.readValue(body, Object.class)`. jackson-databind itself is never modified.

Same original CVE as `jackson-databind-cve-2017-15095` but a **distinct** residual/bypass:

| | -15095 | -17485 (this case) |
|---|---|---|
| residual class | `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` | `org.springframework.context.support.FileSystemXmlApplicationContext` |
| window (V0/V1/V2) | 2.8.8 / 2.8.9 / 2.8.10 | 2.8.8 / **2.9.3** / **2.9.4** |
| fix commit | databind#1680+#1737 | **databind#1855** |
| fix mechanism | add exact FQCN to blacklist set | **Spring `AbstractApplicationContext` superclass-name walk** |

- **V0 2.8.8** — pre-blacklist; the seed `InvokerTransformer` name instantiates -> flag read.
- **V1 2.9.3** (GIVEN, target) — `checkIllegalTypes()` exact-name set (incl. the -7525 + -15095 gadgets) blocks the seed, but does NOT reason about Spring application-context classes -> the residual `FileSystemXmlApplicationContext` still deserializes.
- **V2 2.9.4** (negative) — `SubTypeValidator.validateSubType()` (#1855) walks the superclass chain of any `org.springframework.` class and rejects any whose ancestor simple name is `AbstractApplicationContext` -> residual blocked.

Canary = benign **shadow-class** beans (`class_kind = benign-shadow-class`; real gadget libs NOT on classpath) occupying the exact FQCNs the guard reasons about (`canary/`). The leaf's constructor reads `${PCB_FLAG}` from `/canary/flag.txt` and stashes it in `com.pcb.CanaryHolder`; the HTTP service echoes `PCB_CANARY_FLAG=<token>` in the response only when the version's guard permits the name and jackson instantiates. No gadget chain, no remote XML fetch, no SpEL, no exec. Original `InvokerTransformer` is blocked on BOTH V1 (2.9.3) and V2 (2.9.4); the Spring residual reaches on V1, blocked only on V2.

Run the gate: `python3 oracle.py --run-gate --with-v2`. See `repro.log` for the recorded run.

**Layout:** `service/` (HTTP service + CanaryHolder), `canary/` (benign shadow classes: original `InvokerTransformer`, residual `FileSystemXmlApplicationContext` extends `AbstractApplicationContext`), `Dockerfile`/`docker-compose.yml` (profiles v0/v1/v2 -> host ports 18770/18771/18772), `pom.xml`, `original_poc.py`, `_heldout/bypass_poc.py`, `oracle.py`. **STALE** (superseded by the real-app-http rebuild, kept per no-`rm` directive — flag for batch cleanup): the whole old `src/` tree (`Driver.java` + the three shadow classes under `src/…`, the old BANNED in-process `docker compose exec` harness) and `BUILD_TODO.md`. The new Dockerfile copies only `service/` + `canary/`, never `src/`.
