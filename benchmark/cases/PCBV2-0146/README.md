# moby-docker-engine-cve-2026-34040

Moby / Docker Engine — CVE-2024-41110 -> CVE-2026-34040 (the 41110 fix adds
`|| isChunked(r)` to the AuthZ body-forward predicate but keeps the
`r.ContentLength < maxBodySize` (1 MiB) gate, and `drainBody`'s
`Peek(maxBodySize)` returns a NIL body ("skipping body") for oversized payloads —
so a body >= 1 MiB is never shown to the authorization plugin while the daemon
acts on it; Auth_Bypass; case.json records root_cause `Auth_Bypass`, no CWE ID).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core harness (case.json `flag.resource`): the image runs the REAL Moby
AuthZ-middleware predicate `(*Ctx).AuthZRequest` lifted VERBATIM from
`pkg/authorization/authz.go` at the three tags, wired to a stub AuthZ plugin that
DENIES `POST /v1.45/containers/create` whose body it is SHOWN containing
`"Privileged":true` (default-ALLOWS an empty body — real plugins behave the same
when shown nothing), and a stub daemon that acts on the FULL body and returns
`${PCB_FLAG}` in the create response only iff it actually created a privileged
container. Verified on real Docker 29.4.0; external raw-HTTP trigger over the
published host port.

GHSA-x744-4wpc-v9h2 (case.json `evidence.incomplete_fix_quote`): "This is an
incomplete fix for CVE-2024-41110. ... an attacker could make the Docker daemon
forward the request to an authorization plugin without the body." `patch_real.diff`
is the CVE-2024-41110 fix (commit `fc274cd2…`, v23.0.15/v26.1.5/v27.1.1): adds
`isChunked(r)` to the predicate. The CVE-2026-34040 fix (commit `e89edb19…`,
v29.3.1) drops the size condition and FAIL-CLOSES: `bufio.NewReaderSize(r.Body,
maxBodySize+1)` + `Peek(maxBodySize+1)` success => reject ("request body too
large for authorization plugin").

- **V0 = pre-41110** (`:39680`) — body forwarded only when `ContentLength > 0`;
  the CHUNKED seed (`Transfer-Encoding: chunked`, `ContentLength == -1`) shows the
  plugin an empty body -> ALLOW -> daemon creates privileged -> flag
  (repro.log: FLAG reached).
- **V1 = 41110-patched (v27.1.1)** (`:39681`, target) — the 41110 fix BLOCKS the
  chunked seed (body shown -> DENY), but the OVERSIZED residual (~1.3 MiB padded
  create, `"Privileged":true` intact) fails `ContentLength < maxBodySize` ->
  plugin shown empty -> ALLOW -> daemon reads the full body -> privileged create
  -> flag. Incomplete fix.
- **V2 = 34040-patched (v29.3.1)** (`:39682`, 34040 fix) — fail-closed reject:
  `{"message":"request body too large for authorization plugin: size exceeds 1048576 bytes"}`,
  no flag (repro.log).

- **Original trigger**: `POST /v1.45/containers/create` with
  `Transfer-Encoding: chunked` and body `{"Privileged":true}`
  (`poc/original_poc.py` candidate, `mode: "chunked"`).
- **Residual trigger**: same endpoint with a ~1.3 MiB Content-Length body
  `{"Privileged":true,"pad":"a"*1300*1024}` (`_heldout/bypass_poc.py`
  candidate, `mode: "oversized"`). Control: plain privileged create is DENIED on
  ALL versions (the plugin genuinely guards what it can see).

Run: `python3 oracle.py --run-gate --with-v2` (gate 2026-07-11, flag
`PCBFLAG_6059ca5a0ecde0bfb06c5762c95d0878`: v0 seed FLAG / v1 seed deny / v1
residual FLAG / v2 residual reject; passed=true). See `repro.log` and
`case.json`.

> NOTE: `status.status.review_reason` says "software origin is not classifiable
> ... needs human confirmation" and `execution.software_origin` is `null` — this
> is the faithful-core (lifted-verbatim-predicate) build, not an official-image
> build; the harness (`harness.go` + `go.mod`) is the software under test.
