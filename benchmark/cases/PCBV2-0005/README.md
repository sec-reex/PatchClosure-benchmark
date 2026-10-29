# xstream-cve-2020-26217

XStream — CVE-2013-7285 -> CVE-2020-26217 (Deserialization deny-list, CWE-502 / CWE-184).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Java HTTP service (`com.pcb.XStreamDeserHttpService`, JDK `com.sun.net.httpserver.HttpServer`)
exposes `POST /deser` (text/xml). It deserializes the attacker XML request body via the REAL,
unmodified published `new XStream().fromXML(requestBody)`. Same sink, same XStream DEFAULT deny-list
fix mechanism (`XStream.setupSecurity()`); the advisory calls CVE-2020-26217 "a variation of
CVE-2013-7285".

- **V0 = xstream 1.4.10** (`:18800`) — default deny-list permits `java.beans.EventHandler` -> seed
  reaches the canary.
- **V1 = xstream 1.4.13** (`:18801`, target) — default deny-list DENIES `java.beans.EventHandler` ->
  the -7285 seed is BLOCKED, but `javax.imageio.ImageIO$ContainsFilter` is NOT denied -> the
  CVE-2020-26217 residual still reaches the canary. Incomplete fix.
- **V2 = xstream 1.4.14** (`:18802`, -26217 fix) — default deny-list adds
  `javax.imageio.ImageIO$ContainsFilter` -> residual BLOCKED.

Benign shadow-class channel: the attacker XML body `<list><TRIGGER/><pcb.PcbCanary/></list>` is
POSTed over HTTP; XStream deny-checks TRIGGER first, and only if permitted does it reach the benign
`pcb.PcbCanary` shadow bean, whose registered converter reads a planted `${PCB_FLAG}` file and the
service echoes it in the HTTP response. No gadget chain, no ProcessBuilder, no command execution.

- **Original benign-shadow trigger**: `java.beans.EventHandler` (on the 1.4.13 deny-list).
- **Residual benign-shadow trigger**: `javax.imageio.ImageIO$ContainsFilter` (off the 1.4.13
  deny-list, added in 1.4.14).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

Note: `src/Driver.java` and `src/pcb/PcbCanary.java` are STALE files from the previous in-process
design and are NOT referenced by the current recipe (kept per a no-delete directive).
