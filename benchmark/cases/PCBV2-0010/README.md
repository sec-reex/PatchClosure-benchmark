# traefik-cve-2026-29054

Traefik — CVE-2024-45410 -> CVE-2026-29054 (Connection-token guard compares
case-sensitively while header deletion deletes case-insensitively, CWE-178 /
CWE-348). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL
HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published Traefik official images (`traefik:v2.11.8` / `v2.11.9` /
`v2.11.38`) as a reverse proxy over external HTTP, routing via file-provider
`dynamic.yml` (`PathPrefix(/)` -> internal `upstream` sidecar, `python:3.12-alpine`,
NO host port). Traefik's entrypoint forwardedheaders middleware runs with its
DEFAULT config (`insecure=false`, empty trustedIPs), so Traefik OWNS `X-Real-Ip`:
it clears attacker-supplied X-* headers and rewrites `X-Real-Ip` to the real
client IP — the attacker can only STRIP it, never spoof it. The upstream serves
`${PCB_FLAG}` at the PROTECTED path `/admin/secret` ONLY when the request carries
NO `X-Real-Ip` (identity stripped => trusted internal origin, the advisory's
documented IP-allowlist-bypass impact); with the header present it returns
`forbidden`. Baseline GET is `forbidden` on all three versions, so the flag can
only come from a successful header strip. No gadget chain, no command execution.

`patch_real.diff` is the CVE-2024-45410 upstream fix (commit
`584144100524277829f26219baaab29a53b8134f`, v2.11.9):
`pkg/middlewares/forwardedheaders/forwarded_header.go` grows
`removeConnectionHeaders`, which recognizes Traefik-managed forwarded headers and
drops their tokens from `Connection` so the header survives. Incomplete because
the guard `slices.Contains(xHeaders, sf)` compares the token CASE-SENSITIVELY
against canonical names (`X-Real-Ip`) while the fall-through `req.Header.Del(sf)`
and Go's header map delete CASE-INSENSITIVELY. GHSA-92mv-8f8w-wq52 (case.json
`evidence.incomplete_fix_quote`): "The Connection tokens are compared
case-sensitively against the protected header names, but the actual header
deletion operates case-insensitively. ... a bypass of the fix for CVE-2024-45410."

- **V0 = 2.11.8** (`traefik:v2.11.8`, `:39390`) — no `removeConnectionHeaders`:
  `Connection: close, X-Real-Ip` strips the managed header hop-by-hop -> backend
  sees no identity -> flag (repro.log matrix: 200 FLAG).
- **V1 = 2.11.9** (`traefik:v2.11.9`, `:39391`, target; affected window
  2.11.9..2.11.37, v3 line 3.1.3..3.6.8) — the 45410 fix BLOCKS the canonical
  token (200 `forbidden`), but lowercase `x-real-ip` misses the case-sensitive
  guard and still deletes `X-Real-Ip` -> flag (200 FLAG). Incomplete fix.
- **V2 = 2.11.38** (`traefik:v2.11.38`, `:39392`, 29054 fix; also 3.6.9) —
  `removeConnectionHeaders` canonicalizes first (`http.CanonicalHeaderKey(sf)`)
  -> lowercase recognized as protected, `X-Real-Ip` survives -> `forbidden`.

- **Original trigger**: `GET /admin/secret` with `Connection: close, X-Real-Ip`
  (canonical token; `poc/original_poc.py` `CONNECTION`).
- **Residual trigger**: `GET /admin/secret` with `Connection: close, x-real-ip`
  (lowercase token; `_heldout/bypass_poc.py` `CONNECTION`) — same sink, differs
  ONLY in token case.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate passed=true; full differential matrix: baseline forbidden@all, orig
FLAG@v0/forbidden@v1, residual FLAG@v1/forbidden@v2).

> NOTE: `provenance.notes` says stale lifted-harness files `harness.go` /
> `Dockerfile` / `go.mod` were "left in place per NO-rm policy"; the directory
> currently contains only the stale `Dockerfile` — `harness.go` and `go.mod` are
> absent (the 2026-07-16 rebuild audit already recorded them as unreferenced).
