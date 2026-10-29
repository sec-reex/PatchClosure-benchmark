# resteasy-jboss-cve-2014-3490

RESTEasy (JBoss) XML External Entity injection (XXE, CWE-611) — genuine **incomplete fix**, built as a
**real RESTEasy JAX-RS web app triggered over external HTTP**.

- **CVE-2012-0818** (fixed 2.3.1 / 3.0.x): XXE via external **general** entity in RESTEasy's JAXB
  unmarshalling; fixed by setting `external-general-entities=false` on the SAX `XMLReader` inside
  `ExternalEntityUnmarshaller` (used when `resteasy.document.expand.entity.references=false`).
- **CVE-2014-3490** (RESTEASY-1073, fixed 3.0.9.Final / 2.3.8.SP2): the same guard never disabled
  external **parameter** entities. Red Hat Bugzilla 1107901 / NVD: *"the fix for CVE-2012-0818 was
  incomplete: external parameter entities were not disabled."* In 3.0.9 the fix replaces
  `ExternalEntityUnmarshaller` with `SecureUnmarshaller`, which sets `external-parameter-entities=false`.

## App / trigger
Real RESTEasy JAX-RS app (WAR on Apache Tomcat 8.5, JRE 8). Endpoint `POST /app/xml`
(`Content-Type: application/xml`) unmarshals the body into a JAXB `@XmlRootElement` `Foo` bean via the
real RESTEasy JAXB provider and returns the bean value — so an XXE-injected file read surfaces in the
HTTP response. Canary = read-exfil: `${PCB_FLAG}` planted at `/flag`.

- **Original (given)** — external **general** entity, self-contained body:
  `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag"> ]><foo>&xxe;</foo>`.
- **Residual (held-out)** — external **parameter** entity; the benign exfil DTD (XML forbids the
  general-entity-redefinition trick in a document's internal subset) is served by the oracle on the
  host-gateway (the "attacker DTD server" role, local test rig — no external host). The secret read is
  a local `file:///flag` returned in-band.

Versions (real published Maven Central artifacts): V0 = 2.3.0.GA · V1 (target) = 3.0.8.Final · V2 = 3.0.9.Final.

## Differential
| | original (general entity) | residual (parameter entity) |
|---|---|---|
| V0 2.3.0.GA | REACHES | (reaches) |
| V1 3.0.8 | BLOCKED (`external-general-entities=false`) | **REACHES** ← incomplete fix |
| V2 3.0.9 | (blocked) | BLOCKED (`external-parameter-entities=false`) |

Gate: `python3 oracle.py --run-gate --with-v2` → passed=true (see `repro.log`).

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

## NOTE — stale files
`Driver.java` is a **stale leftover** from the previous in-process (reflection) build and is no longer
referenced by `docker-compose.yml`, `Dockerfile`, `case.json`, or `oracle.py`. The live web-app build
uses `pom.xml` + `src/main/**` + `Dockerfile` + `docker-compose.yml`.
