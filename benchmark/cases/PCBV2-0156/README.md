# oauth2-proxy-cve-2026-40575

OAuth2-Proxy — CVE-2025-54576 -> CVE-2026-40575 (the 7.11.0 fix switches
`isAllowedPath` from `GetRequestURI` (full URI incl. `?query`) to
`GetRequestPath`, but `GetRequestPath` still derives the path from the
CLIENT-SUPPLIED `X-Forwarded-Uri` header whenever `--reverse-proxy` is on, so a
spoofed header matches the `skip_auth_route` while the real path is proxied
upstream; Auth_Bypass, CWE-290). **Genuine incomplete fix; gate passed on real
Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published oauth2-proxy per version (official `quay.io/oauth2-proxy/
oauth2-proxy:v7.10.0` / `:v7.11.0` / `:v7.15.2` images, `--reverse-proxy` mode,
dummy OIDC provider config, real `--skip-auth-route=^/foo/.*/bar$`) in front of
an internal `upstream` sidecar (`python:3.12-alpine`, NO host port) that serves
`${PCB_FLAG}` ONLY at the PROTECTED path `/foo/critical_endpoint` and a benign
`public-ok` at the genuinely-public skip route `/foo/health/bar` and elsewhere —
oauth2-proxy is the SOLE auth gate. Authz-seeded: the flag returns iff an
unauthenticated external request tricks the skip-auth decision so the protected
upstream path is reached. Baseline `GET /foo/critical_endpoint` is 403 on all
three versions (genuinely OIDC-gated).

`patch_real.diff` is the CVE-2025-54576 fix (commit
`9ffafad4b2d2f9f7668e5504565f356a7c047b77`, v7.11.0 / GHSA-7rh7-c77v-6434).
GHSA-7x63-xv5r-3p2x (case.json `evidence.incomplete_fix_quote`): "OAuth2 Proxy
may trust a client-supplied X-Forwarded-Uri header when --reverse-proxy is
enabled and --skip-auth-route or --skip-auth-regex is configured. An attacker can
spoof this header so OAuth2 Proxy evaluates authentication and skip-auth rules
against a different path than the one actually sent to the upstream application."
The v7.15.2 fix gates `X-Forwarded-*` on `CanTrustForwardedHeaders` /
`--trusted-proxy-ip` (this case sets `--trusted-proxy-ip=10.99.99.0/24`,
excluding the direct attacker — the default trusts ALL IPs, so it must be set).

- **V0 = v7.10.0** (`:39380`) — `isAllowedPath` matches the full URI:
  `GET /foo/critical_endpoint?param=/bar` satisfies `^/foo/.*/bar$` -> auth
  skipped -> flag (repro.log: 200 FLAG).
- **V1 = v7.11.0** (`:39381`, target; differential window v7.11.0..v7.15.1) —
  the 54576 fix BLOCKS the query seed (403; `GetRequestPath` strips the query),
  but `GET /foo/critical_endpoint` with header `X-Forwarded-Uri: /foo/anything/bar`
  makes the skip check match while the REAL path is proxied -> 200 FLAG.
  Incomplete fix.
- **V2 = v7.15.2** (`:39382`, 40575 fix) — untrusted direct caller's spoofed
  header ignored -> falls back to the real path -> 403, no flag (repro.log).

- **Original trigger**: `GET /foo/critical_endpoint?param=/bar`, no session,
  no forwarded header (`poc/original_poc.py` candidate).
- **Residual trigger**: `GET /foo/critical_endpoint` with
  `X-Forwarded-Uri: /foo/anything/bar` (`_heldout/bypass_poc.py` candidate:
  `REAL_PATH` + `SPOOF_URI` header).

Run: `bash run_gate.sh` / `python3 oracle.py --run-gate --with-v2` (gate on real
Docker, flag `PCBFLAG_66794bfc…`: orig@v0=200 FLAG / orig@v1=403 / orig@v2=403 /
residual@v1=200 FLAG / residual@v2=403; passed=true). See `repro.log` and
`case.json`.

> NOTE: `Dockerfile` + `harness.go` + `go.mod` are the OLD faithful-core harness
> (verbatim lift of `GetRequestURI`/`GetRequestPath`/`CanTrustForwardedHeaders`);
> per case.json `audit` they are NO LONGER used by `docker-compose.yml` and are
> retained as stale offender files per the no-rm rule.
