# apache-http-server-mod-proxy-cve-2011-3639

Apache HTTP Server (mod_proxy) — CVE-2011-3368 -> CVE-2011-3639 (the request-URI
guard was added to the mod_rewrite translate hook only; the sibling ProxyPassMatch
front-end reached the same mod_proxy routing sink unguarded; reverse-proxy SSRF,
CWE-918). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL
HTTP.**

分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Apache httpd 2.2.21 compiled from source (archive.apache.org tarball,
`debian:bullseye-slim`) in three patchlevels via `patch_source.py`: V0 pristine /
V1 `mod_rewrite.c::hook_uri2file` guard only / V2 `mod_rewrite.c` +
`mod_proxy.c::proxy_trans` guards (== 2.2.22). Each image exposes TWO
reverse-proxy front-ends onto the SAME mod_proxy routing sink: `:80` =
`RewriteRule .* http://legit-backend%{REQUEST_URI} [P]`, `:8080` =
`ProxyPassMatch ^(.*)$ http://legit-backend$1` (classic no-`/` mis-configuration).
SSRF sidecar canary: the internal-only `sidecar` service (no host port) echoes
`${PCB_FLAG}` for any path on `:80`; the intended backend is `legit-backend`. The
raw-socket request-target `@sidecar/` is expanded to
`http://legit-backend@sidecar/` — `legit-backend` degrades to userinfo and the
internal host becomes the proxy target, so the flag body is proxied straight back.

NVD on CVE-2011-3639 (case.json `evidence.incomplete_fix_quote`): "does not
properly interact with use of (1) RewriteRule and (2) ProxyPassMatch pattern
matches ... NOTE: this vulnerability exists because of an incomplete fix for
CVE-2011-3368." `patch_real.diff` is the CVE-2011-3368 fix
(`3597dd02149a842e18c9074fc39a3cc1baaf889b`): `server/protocol.c
read_request_line` rejects a request-URI with no scheme, not starting with `/`
and not `*` (400) unless CONNECT; the per-hook guards (`r->uri[0] != '/'` ->
DECLINED) land in the two translate hooks. V1 applies ONLY the mod_rewrite one.

- **V0 = 2.2.21 pristine** (`pcb-httpd:2.2.21-v0`, `:38260` rewrite / `:38263`
  proxypass) — neither hook validates the request-URI -> `@sidecar/` reaches the
  sidecar via BOTH front-ends (repro.log: 200 + FLAG both).
- **V1 = 2.2.21 + mod_rewrite guard** (`:38261` / `:38264`, target) — the 3368
  fix BLOCKS the RewriteRule vector (`GET @sidecar/` -> 400 Bad Request, hook
  DECLINEs the non-`/` URI), but the ProxyPassMatch front-end is still guarded by
  nothing (`proxy_trans` returns OK for an already-set `r->proxyreq` before any
  guard) -> same `@sidecar/` target routes to the sidecar -> 200 + FLAG.
  Incomplete fix.
- **V2 = 2.2.21 + both guards (== 2.2.22)** (`:38262` / `:38265`, completing fix
  held out under `_heldout/cve-2011-3639_fix.diff`) — both front-ends 400.

- **Original trigger**: raw `GET @sidecar/ HTTP/1.0` to the RewriteRule vhost
  `:80` (`poc/original_poc.py` `RAW`, `route: "rewrite"`).
- **Residual trigger**: the SAME `@sidecar/` request-target to the ProxyPassMatch
  vhost `:8080` (`_heldout/bypass_poc.py` `RAW`, `route: "proxypass"`).
  Liveness control: normal `GET /` reaches legit-backend on all 6 endpoints.

Run: `python3 oracle.py --gate` (gate 2026-07-11, flag
`PCBFLAG_d8e1bb80a5db615028920af970dcee1f`: v0 seed FLAG / v1 seed 400 / v1
residual FLAG / v2 residual 400; passed=true). See `repro.log` and `case.json`.

> NOTE: the Dockerfile header comment says "PATCHLEVEL selects the
> server/protocol.c patch level ... See patch_protocol.py", but the build copies
> and runs `patch_source.py`, and case.json/repro.log state the per-version delta
> is in `mod_rewrite.c` / `mod_proxy.c` translate hooks (V1 is NOT an upstream
> patched release — it is 2.2.21 with only the rewrite-guard section applied).
> The Dockerfile comment is stale relative to the actual recipe.
