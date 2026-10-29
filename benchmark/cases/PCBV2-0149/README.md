# netty-cve-2020-7238

Netty — CVE-2019-16869 -> CVE-2020-7238 (the 4.1.42 fix stops whitespace before
the colon breaking the header-name loop in `splitHeader`, but `readHeaders` still
accepts a request carrying BOTH `Content-Length` AND `Transfer-Encoding: chunked`
— chunked silently overrides CL with no error, the CL.TE conflict the whitespace
fix never covered; HTTP request smuggling, CWE-444). **Genuine incomplete fix;
gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core: each service is a `maven:3.9-eclipse-temurin-8` build of a tiny,
UNMODIFIED Netty origin server (`HttpServerCodec` + `HttpObjectAggregator` + a
`/flag` router) resolving `io.netty:netty-codec-http` at the pinned version
(4.1.41.Final / 4.1.43.Final / 4.1.44.Final) from Maven Central; the version's
own `HttpObjectDecoder` is the framing guard under test. Request-smuggling
canary: the oracle sends RAW crafted bytes over a socket; an internal `GET /flag`
route returns `${PCB_FLAG}` and is reached ONLY when the pipelined smuggled
request is decoded as a second request on the connection — a rejected front
request enters BAD_MESSAGE (400 + close) and the trailing bytes are swallowed,
never decoded.

NVD (case.json `evidence.incomplete_fix_quote`): "Netty 4.1.43.Final allows HTTP
Request Smuggling ... NOTE: this issue exists because of an incomplete fix for
CVE-2019-16869." `patch_real.diff` is the CVE-2019-16869 fix (commit
`39cafcb05c99f2aa9fce7e6597664c9ed6a63a95`, PR #9585,
`HttpObjectDecoder.splitHeader`): whitespace no longer breaks the name loop for
requests. The CVE-2020-7238 fix (commit `8494b04…`, PR #9865, 4.1.44) makes
`readHeaders` throw `Both 'Content-Length: N' and 'Transfer-Encoding: chunked'
found`.

- **V0 = 4.1.41.Final** (`:39760`) — seed `POST /` with
  `Transfer-Encoding : chunked` (SP before colon) is read as valid chunked ->
  empty chunked body ends the request -> smuggled `GET /flag` decoded -> flag
  (repro.log: reaches).
- **V1 = 4.1.43.Final** (`:39761`, target) — the 16869 fix BLOCKS the
  whitespace seed (SP stays in the name -> DefaultHttpHeaders rejects ->
  400), but the clean CL.TE conflict `Content-Length: 5` +
  `Transfer-Encoding: chunked` is accepted (chunked silently wins) -> same
  smuggle -> flag. Incomplete fix. (Both orderings — CL-then-TE and TE-then-CL —
  work; `_heldout` VECTORS.)
- **V2 = 4.1.44.Final** (`:39762`, 7238 fix) — CL+TE:chunked throws -> 400, no
  flag; the whitespace rejection is still present (repro.log negative controls).

- **Original trigger**: raw `POST /` with
  `Transfer-Encoding : chunked`, empty chunked body `0\r\n\r\n`, pipelined
  `GET /flag` (`poc/original_poc.py` `build_smuggle`, candidate
  `id: "cve-2019-16869-te-space-before-colon"`).
- **Residual trigger**: same framing with front headers
  `Content-Length: 5\r\nTransfer-Encoding: chunked` (clean CL.TE conflict;
  `_heldout/bypass_poc.py` `VECTORS`, reusing `build_smuggle`).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-13, flag
`PCBFLAG_5c0cdaf0a128e2b7b7f57f663a2df8a8`: v0 seed FLAG / v1 seed 400 / v1
residual FLAG / v2 residual 400; passed=true). See `repro.log` and `case.json`.
