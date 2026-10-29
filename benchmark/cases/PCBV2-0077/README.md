# apache-log4j-2-cve-2021-45046

Apache Log4j 2 — CVE-2021-44228 (Log4Shell) -> CVE-2021-45046 (Expression-Language / JNDI
Lookup Injection, CWE-917). The canonical genuine incomplete fix: 2.15.0 fixed CVE-2021-44228,
but the fix was incomplete and CVE-2021-45046 remained until 2.16.0.

- **V0** = log4j-core **2.14.1** — message-text lookups ON; a plainly logged `${jndi:ldap://...}`
  fires the JNDI lookup.
- **V1** = log4j-core **2.15.0** (=CVE-2021-44228 patched, **target**) — message-text lookups OFF
  by default (plain vector blocked), BUT the context-lookup/MDC layout path still interpolates
  `${jndi:...}` and 2.15.0's default allowed-hosts includes `127.0.0.1`, so an allowed JNDI still
  resolves — the CVE-2021-45046 residual.
- **V2** = log4j-core **2.16.0** (=CVE-2021-45046 patched) — message lookups removed + JNDI
  disabled by default → blocked.

Faithful-core: the real published log4j-core/log4j-api jars are pulled from Maven Central and
driven through the ordinary public `Logger` + `ThreadContext` API (`Driver.java`), with a shared
unmodified `log4j2.xml` whose PatternLayout uses `$${ctx:pcbctx}`. The canary is a **benign**
internal LDAP listener on `127.0.0.1:1389` (`ldap_canary.py`) that only records an inbound JNDI
connection and echoes the planted `${PCB_FLAG}` — no gadget, no class-load, no deserialization.

Gate: `python3 oracle.py --run-gate --with-v2` → all three checks true, residual blocked on V2.
Status: **gate_passed** (see `repro.log`). See `../SPEC.md`.

分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
