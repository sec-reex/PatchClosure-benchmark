# python-urllib-urllib2-cve-2019-18348

Python stdlib urllib / http.client — CVE-2019-9740 -> CVE-2019-18348 (CRLF / HTTP Header
Injection, CWE-93). **Genuine incomplete fix** — same file (`Lib/http/client.py`), same sink
(`HTTPConnection.putrequest`), same guard regex (`_contains_disallowed_url_pchar_re`); the
CVE-2019-9740 fix validated only the URL **path**, missing the **host** component.

- **V0** = python 3.7.3 (pre-fix): neither `_validate_path` nor `_validate_host`; a CRLF in the
  request path splits off a smuggled inline command.
- **V1** = python 3.7.7 (**CVE-2019-9740 path fix**, target): `putrequest` calls
  `_validate_path(url)`, so the path-CRLF **seed is blocked**. But `self.host` is **not** validated,
  so a CRLF in the URL **host** component still reaches the wire (residual reaches the flag on V1).
- **V2** = python 3.7.8 (**CVE-2019-18348 host fix**): `HTTPConnection.__init__` now calls
  `_validate_host(self.host)` (same regex), rejecting the CRLF host at construction (blocked).

Mechanism nuance: `putheader`'s pre-existing `_is_illegal_header_value` rejects a *bare* CRLF
header value on all three versions, so the host residual uses an **obs-fold** (`\r\n ` + inline
`GET flag`) that this regex explicitly permits — exactly what `_validate_host` was added to close.

Canary = a benign internal line-based listener on `127.0.0.1:9000` (no host port); the planted
`${PCB_FLAG}` is returned only when an injected inline `GET flag` line reaches it (Redis-style
inline parsing — the real CVE-2019-18348 impact class). Faithful-core: official `python:3.7.x-slim`
images run the REAL, unmodified stdlib `http.client`; nothing in CPython is modified.

Gate (real Docker): `python3 oracle.py --run-gate --with-v2` → `passed=true`
(reach@v0, blocked@v1, bypass_reach@v1, residual_blocked@v2). See `repro.log` and `case.json`.
