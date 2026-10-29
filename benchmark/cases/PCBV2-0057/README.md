# cpp-httplib-crlf-cve-2025-0825

cpp-httplib (yhirose) — CVE-2020-11709 -> CVE-2025-0825 (CRLF response-header injection, CWE-93 / CWE-113).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (raw socket).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Three `gcc:12` images each compile the identical ~30-line C++ server (`server.cpp`) against the REAL,
unmodified `httplib.h` fetched (Dockerfile `ADD`) from the yhirose/cpp-httplib repo at pinned release
tags. The single handler `GET /echo` reflects the query param `x` (percent-decoded, so `%00` becomes a
real NUL and `%0d%0a` real CRLF inside the `std::string`) into a RESPONSE header via
`res.set_header("X-Echo", echoed)` — the exact sink whose CRLF-sanitization evolved across the chain.
The oracle drives the service over a RAW SOCKET (no normalizing HTTP client) and passes iff the raw
response bytes contain the line sequence `\r\nX-Pcb-Inject: <PCB_FLAG>\r\n` — a benign marker header
the CRLF payload tries to split into the response.

- **V0 = v0.5.8** (`:18080`) — `Response::set_header` does a raw `headers.emplace()` (no filter) -> the
  plain-CRLF seed splits the response and the `X-Pcb-Inject` line appears on the wire.
- **V1 = v0.18.3** (`:18081`, target) — CVE-2020-11709 fix: `set_header` / `set_redirect` guard with
  `detail::has_crlf`, which walks `val.c_str()` and STOPS at the first NUL -> the plain-CRLF seed is
  BLOCKED (no emplace), but a NUL byte PREFIXED to the CRLF hides it from the scan while `emplace`
  stores the full `std::string` and `write_headers` writes it out by length -> the CVE-2025-0825
  residual still injects (`X-Echo: SAFE\x00` followed by the injected `X-Pcb-Inject: <FLAG>` line on
  the wire). Incomplete fix.
- **V2 = v0.18.4** (`:18082`, -0825 fix, commit `9c36aae`) — `set_header` replaces `has_crlf` with
  `detail::fields::is_field_value()`, a length-based RFC field-content check that indexes by
  `s.size()` and inspects EVERY byte including those after a NUL (NUL/CR/LF are not vchars) ->
  residual BLOCKED.

- **Original trigger**: `GET /echo?x=SAFE%0d%0aX-Pcb-Inject:%20<PCB_FLAG>` — plain CRLF inside the
  reflected value; visible to `has_crlf`, so blocked on V1/V2.
- **Residual trigger**: `GET /echo?x=SAFE%00%0d%0aX-Pcb-Inject:%20<PCB_FLAG>` — a NUL before the CRLF;
  `has_crlf(val.c_str())` stops at the NUL and passes the value, which is then emplaced and written
  whole.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

Note: on V0 the NUL-prefixed residual does NOT inject — v0.5.8's `write_headers` serializes with
`write_format("%s: %s\n", val.c_str())`, whose `%s` truncates at the NUL, so the split header is not
emitted pre-fix (honest sanity note in `repro.log`); V0 is measured with the plain-CRLF original,
which does inject. The four required gate booleans are unaffected.
