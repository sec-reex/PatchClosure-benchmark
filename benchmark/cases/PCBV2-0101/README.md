# deser_sofahessian_blacklist

SOFA Hessian — CVE-2019-9212 -> CVE-2024-46983 (Deserialization deny-list, CWE-184 / CWE-502).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

A REAL small Java HTTP service (`com.pcb.HessianDeserService`, JDK built-in
`com.sun.net.httpserver.HttpServer`) exposes `POST /deser`. It deserializes the attacker Hessian2
request body through the REAL, unmodified published `com.alipay.sofa:hessian` jar's own default
blacklist (`ClassNameResolverBuilder.buildDefault()` -> `NameBlackListFilter` over the bundled
`security/serialize.blacklist`, case-sensitive `className.startsWith`), reached exactly as a SOFA-RPC
service would. Same sink, same blacklist-fix mechanism (den entries added / broadened).

- **V0 = sofa-hessian 3.3.13** (`:18790`) — bundled blacklist has NO `com.caucho.naming` /
  xpath entries (pre-CVE-2019-9212) -> the seed name resolves -> seed reaches the canary.
- **V1 = sofa-hessian 3.5.4** (`:18791`, target) — CVE-2019-9212 fix ADDS the entries VERBATIM as the
  lowercase-typo'd `com.caucho.naming.Qname` and `com.sun.org.apache.xpath.internal.objects.Xstring`:
  the exact-typo seed name is BLOCKED (`Class com.caucho.naming.Qname is in blacklist.`), but the
  correctly-cased real gadget FQCN `...XString` never `startsWith`-matches the typo, and the narrow
  per-class enumeration misses the rest of `com.sun.*` -> the residual REACHES the canary.
  Incomplete fix. (slf4j + sofa-common-tools + logback are pulled because the filter only throws when
  its slf4j LOGGER is non-null — without them the guard silently no-ops.)
- **V2 = sofa-hessian 3.5.5** (`:18792`, -46983 fix) — narrow enumeration REPLACED by broad package
  prefixes incl. `com.sun.` -> residual BLOCKED (`Class ...XString is in blacklist.`).

Benign shadow-class channel: an EXTERNAL `POST /deser` carries a benign Hessian2 typed-map body
(`{"probe": <fqcn>}`, REAL `Hessian2Output` encoding from `attacker/StreamGen.java`) naming the probe
class; if `resolve()` lets the NAME through, the service reads the planted `/canary/flag.txt`
(OUTSIDE the app dir) and echoes `PCB_CANARY_FLAG=<token>` in the HTTP response. The body carries only
the class NAME + a 2-string map, never the flag. No gadget chain, no ProcessBuilder, no command
execution.

- **Original benign-shadow trigger**: `com.caucho.naming.Qname` — verbatim the lowercase-typo'd
  CVE-2019-9212 blacklist entry (a benign classpath canary jar makes it genuinely resolvable);
  blocked on 3.5.4.
- **Residual benign-shadow trigger**: `com.sun.org.apache.xpath.internal.objects.XString` (the real
  JDK/Resin XString gadget FQCN, capital S) — misses 3.5.4's case-typo'd `...Xstring` entry and the
  narrow enumeration; caught by 3.5.5's broad `com.sun.` prefix.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE: the case.json provenance notes flag a stale old in-process harness (`src/com/pcb/Harness.java`
> + `src/`), but no `src/` directory exists in the case dir anymore; the current design dirs are
> `attacker/`, `canary/`, `service/`.
