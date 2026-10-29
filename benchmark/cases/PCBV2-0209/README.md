# undertow-jboss-wildfly-web-server-cve-2018-1067

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。


Undertow — CVE-2016-4993 -> CVE-2018-1067 (HTTP response splitting / CRLF header injection,
CWE-113). **Genuine incomplete fix** — CVE-2018-1067 is officially titled "HTTP header injection
using CRLF (incomplete fix of CVE-2016-4993)". Same sink (`HttpResponseConduit.writeString`), same
fix lineage, NOT same-release.

- **V0** = undertow-core 1.4.2.Final (pre-4993): `writeString` writes every char raw
  (`buffer.put((byte) charAt(i))`) — a plain CRLF in a reflected header value splits the response.
- **V1** = undertow-core 1.4.3.Final (**exact CVE-2016-4993 fix**, target): `writeString` adds a
  **char-based** guard `if(c != '\r' && c != '\n') buffer.put((byte) c);` — plain CRLF is **blocked**
  (folded to spaces). But it compares the wide `char` while writing `(byte) c`, so a char whose low
  byte narrows to 0x0D/0x0A (**U+010D -> CR, U+010A -> LF**) passes the check and a **real CRLF still
  splits** the response (residual reaches the flag on V1).
- **V2** = undertow-core 1.4.25.Final (**exact CVE-2018-1067 fix**, commit `85d4478`): `writeString`
  narrows to a **byte first** (`byte b=(byte)c; if(b != '\r' && b != '\n')`), catching U+010D/U+010A
  (blocked).

Faithful-core, REAL running server: the REAL `io.undertow:undertow-core` is pulled from Maven
Central and run, unmodified, by `ReflectServer.java` — a tiny Undertow HTTP server bound
`0.0.0.0:8080` and **published to a host port** (v0=39733, v1=39734, v2=39735) that reflects a
request param into a response header. The trigger is fully **EXTERNAL**: `oracle.py` opens a raw
TCP socket from the host to the published port, sends one crafted `GET /reflect?v=...` carrying the
CRLF payload, reads the raw response bytes, and structurally confirms a genuine standalone
CRLF-framed `X-Split` header (i.e. the response actually split past the version's `writeString`
guard). The planted `${PCB_FLAG}` is the per-run answer key released only on a confirmed split; a
random per-probe marker — never the flag — rides the wire.

Gate (real Docker, external raw-HTTP socket): `python3 oracle.py --run-gate --with-v2` → `passed=true`
(reach@v0, blocked@v1, bypass_reach@v1, residual_blocked@v2). See `repro.log` and `case.json`.

STALE (left in place per no-rm policy, NOT wired into the build/oracle): `attack.py` — the old
in-container raw-socket detector from the banned `docker compose exec` design; superseded by the
host-side detector in `oracle.py`.
