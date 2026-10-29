# webrick-crlf-2017-17742-2019-16254

Ruby WEBrick — CVE-2017-17742 -> CVE-2019-16254 (CRLF / HTTP response-header injection /
response splitting, CWE-113).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL WEBrick server (`server.rb`, `WEBrick::HTTPServer` on `:8080`) reflects the query param
`?x=<value>` straight into the RESPONSE header `X-Reflected`. The version boundary lives in Ruby
MRI's BUNDLED webrick: `WEBrick::HTTPResponse#send_header` runs `check_header(value)` on every
header value at write time, and the per-version CR/LF regex there decides whether the value is
written to the socket or triggers an `InvalidHeader` -> 500. The standalone webrick gem skips the
incomplete state (1.4.2 no-check -> 1.4.4 complete `/[\r\n]/`), so each version is a matching
`ruby:2.5.x-slim` base image (the incomplete `/\\r\\n/`-only state shipped only in MRI 2.5.1..2.5.6).

- **V0 = ruby:2.5.0-slim (bundled webrick 1.4.2)** (`:39341`) — `send_header` has NO
  `check_header`; any control chars are written verbatim -> the CRLF-pair split lands, flag
  appears in the raw response bytes.
- **V1 = ruby:2.5.1-slim** (`:39342`, target) — CVE-2017-17742 fix (MRI r62968 / webrick
  7018305) adds `check_header` with `header_value =~ /\r\n/`, raising `InvalidHeader` on the
  full CR-LF PAIR (headers/cookies cleared, 500, retry) -> the CRLF seed is BLOCKED. But an
  isolated LF (or CR) does not match the pair regex -> the CVE-2019-16254 residual still splits
  the header stream. Incomplete fix.
- **V2 = ruby:2.5.8-slim** (`:39344`, -16254 fix, webrick 8658b1b) — `check_header` changed to
  `/[\r\n]/ =~ header_value`, rejecting ANY isolated CR or LF -> residual BLOCKED.

Flag channel: no canary is planted in the container. The per-run `${PCB_FLAG}` token is embedded
by the PoC itself into the CR/LF payload (`X-Pcb-Injected: <flag>` line); it materialises in the
raw HTTP response ONLY when WEBrick's `check_header` ACCEPTS the control-char-bearing `X-Reflected`
value and writes it to the socket. Detector = flag-token substring in the raw response bytes
(response surface only). No shell, no command execution — the canary is response-stream integrity.

- **Original trigger**: `GET /?x=pcbseed%0d%0aX-Pcb-Injected: <flag>` — value
  `pcbseed\r\nX-Pcb-Injected: <flag>`, the full CR-LF pair that V1's `/\r\n/` check rejects
  (500, flag absent); on V0 it splits and the flag lands.
- **Residual trigger**: `GET /?x=pcbseed%0aX-Pcb-Injected: <flag>` — value
  `pcbseed\nX-Pcb-Injected: <flag>`, an isolated LF with no preceding CR that slips past V1's
  `/\r\n/` pair check (isolated CR is missed identically); V2's `/[\r\n]/` character class
  rejects it. Same `X-Reflected` header sink, same CR/LF char class — the incompleteness is the
  missed CHARACTER FORM, exactly as the ruby-lang.org advisory states.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.

> NOTE: V2 port mismatch — `case.json` gives v2 `base_url` `http://127.0.0.1:39343`, but
> `docker-compose.yml` maps v2 to `${PORT_V2_0:-39344}:8080` (default 39344). → 已于 2026-10-11 修复：case.json `versions.v2.base_url` 已改为 `http://127.0.0.1:39344`（以 docker-compose.yml:26 默认映射与 oracle.py:43 为准）。
> NOTE: CVE-2019-16254 fix commit mismatch — `case.json` and `repro.log` cite webrick fix
> `8658b1b`, while `INCOMPLETE_FIX_ANALYSIS.md` cites `3ce238b` for the same fix.
