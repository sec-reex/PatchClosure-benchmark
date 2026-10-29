# dos_rack_byte_ranges

Rack (RubyGems) — CVE-2024-26141 -> CVE-2026-34826 (Byte-range multipart-assembly DoS,
CWE-400 / CWE-770).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (dos-threshold oracle).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

A REAL Rack web app (`app/server.rb`: WEBrick driven through the published `rackup` handler,
`Rackup::Handler::WEBrick`) serves a generated 900000-byte static file through the REAL published
`Rack::Files` middleware on `GET /file`. An EXTERNAL HTTP `GET /file` with a crafted `Range:` header
drives `Rack::Utils.get_byte_ranges` -> `Rack::Files` multipart/byteranges assembly (one multipart
heading + seek/read per range), so cost scales with range count and total assembled bytes. Same sink
across all three versions; each fix edits that same method. No vendored/edited Rack source.

- **V0 = rack 3.0.9** (`:28241`) — `get_byte_ranges` has NO aggregate check at all -> the original
  6000 full-file ranges (total coverage 5.4 GB >> the 900 KB file) are fully assembled (multi-GB) ->
  OOM-kills the 512m container (sentinel 15000 ms; `OOMKilled=true`). Seed reaches.
- **V1 = rack 3.1.20** (`:28243`, target) — CVE-2024-26141 fix adds ONE aggregate guard
  `return [] if ranges.map(&:size).sum > size` -> the original is rejected (416, fast). But there is
  NO cap on the NUMBER of ranges -> 700000 tiny `0-0` ranges whose summed size 700000 <= 900000 PASS
  the coverage check and still force 700000 multipart parts (~52 MB body) -> the residual REACHES
  (206, ~2.9 s). Incomplete fix.
- **V2 = rack 3.1.21** (`:28244`, -34826 fix, commit 345a4cfa) — `get_byte_ranges` gains a
  `max_ranges: 100` keyword and `return nil if byte_range.count(',') >= max_ranges`; nil is treated
  as "no range requested" -> the whole file is served once (200, fast). Coverage check retained.

Resource channel (dos-threshold; no canary token): the signal is SERVER-SIDE latency of the external
GET, measured as the client round-trip under a 15 s read timeout (a hang is recorded as the 15000 ms
sentinel; an OOM-crash/reset verified via `docker inspect .State.OOMKilled` is a DoS-positive).
Containers are pinned `cpus=1.0`, `mem_limit=512m`, and the oracle brings a FRESH server up per probe
so a crash never poisons the next. Thresholds: DoS iff latency > T_SLOW (1000 ms) or crash; benign
fast iff < T_FAST (50 ms). A sidecar watchdog (`watchdog.py`, `:28248`) polls `/health` and releases
the start-injected `${PCB_FLAG}`.

- **Original trigger**: `Range: bytes=0-899999,...` (6000 copies of the full-file range, ~54 KB
  header; total coverage 5.4 GB >> 900 KB) — memory-exhaustion assembly on V0; V1's
  total-coverage guard rejects it -> 416.
- **Residual trigger**: `Range: bytes=0-0,...` (700000 copies of the 1-byte range, ~2.8 MB header;
  summed size 700000 <= file size, COUNT huge) — passes V1's coverage check and still forces
  700000 parts (~52 MB, observed 206 @ ~2.9 s, 1787.8x over benign); V2's count cap turns it into a
  200 whole-file serve (~111 ms, 20.2x reduction).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log`, `gate_result.json`, and `case.json`.

> NOTE: WEBrick hard-codes a 112 KiB request-header limit that would 413-reject the ~2.8 MB residual
> Range header before it reaches Rack; `app/server.rb` raises it to 8 MiB — a WEB-SERVER config
> change (analogous to nginx `large_client_header_buffers`), not a change to Rack or the app logic.
> Default header caps on most front-ends incidentally blunt this count-DoS unless configured for
> large headers. Also: the measured residual latencies differ slightly between `repro.log`
> (~2860.5 ms on V1) and `gate_result.json` (2864.4 ms) — separate runs of the same probe.
