# netty-cve-2026-42578

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Netty — CVE-2025-67735 -> CVE-2026-42578 (CRLF Injection / HTTP request-line & header splitting,
CWE-93 / CWE-113). **Genuine incomplete fix** — GHSA-45q3-82m4-75jr is titled
"HTTP Header Injection via HttpProxyHandler Disabled Validation (Incomplete Fix CVE-2025-67735)".

- **V0** = netty 4.1.128.Final (pre-67735): request-URI CRLF splits off a smuggled request.
- **V1** = netty 4.1.129.Final (**exact CVE-2025-67735 fix**, target): `DefaultHttpRequest` now
  validates the request line (`HttpUtil.validateRequestLineTokens`), so the URI-injection **seed is
  blocked**. But `HttpProxyHandler.newInitialMessage()` still hard-codes
  `DefaultHttpHeadersFactory.headersFactory().withValidation(false)` and adds attacker
  `outboundHeaders` without a CRLF check — so a CRLF in a **CONNECT proxy header value still
  splits** (residual reaches the flag on V1).
- **V2** = netty 4.1.133.Final (**exact CVE-2026-42578 fix**): `validateInitialHeaders` defaults
  true, so the CONNECT header value is validated and the CR (`0x0d`) is rejected (blocked).

**Topology (real-app / external-HTTP):** per version, two SEPARATE containers — `app-vN`
(`App.java`, a real unmodified Netty HTTP server+client built against the pinned io.netty modules)
and `sidecar-vN` (`proxy_sidecar.py`, a real separate proxy container). An **EXTERNAL HTTP POST**
from the oracle to the app's own endpoint (`POST /fetch` seed | `POST /proxyfetch` residual;
attacker value delivered raw, CRLF preserved, in the body) makes the app drive the REAL Netty
client to an OUTBOUND request against the sidecar over the docker network. The CRLF split is
observed at the sidecar's raw wire log — the benign `${PCB_FLAG}` is echoed only when a genuine
CRLF-split `GET /flag` request line reaches it. No Netty code is modified; no in-process driving.

Gate (real Docker): `python3 oracle.py --run-gate --with-v2` → `passed=true`
(reach@v0, blocked@v1, bypass_reach@v1, residual_blocked@v2). See `repro.log` and `case.json`.

**Files:** new build = `docker-compose.yml`, `Dockerfile.app`, `Dockerfile.sidecar`, `App.java`,
`proxy_sidecar.py`, `oracle.py`, `original_poc.py`, `_heldout/bypass_poc.py`, `patch.diff`.
STALE (from the banned in-process build, unreferenced, kept per NO-rm directive): `Dockerfile`,
`Driver.java`, `smuggle_canary.py`.
