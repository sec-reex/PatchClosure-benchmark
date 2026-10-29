# gitea-cve-2026-24791

Gitea — CVE-2025-68941 -> CVE-2026-24791 (the `checkTokenPublicOnly()` guard was
wired onto the public-facing `/api/v1/users/{username}` group but never onto the
`/api/v1/user` SELF-route family, so a `public-only`-scoped token still reads its
own PRIVATE owner's account; incorrect authorization, CWE-863). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL published Gitea per version (official `gitea/gitea:1.22.2` / `1.26.1` /
`1.26.2` images, SQLite, `INSTALL_LOCK=true`) — no source lift, no harness. All
seeding goes through the real Gitea CLI + REST API (`seed.sh`): a PRIVATE
individual account `alice` (`visibility=private`) whose email is
`${PCB_FLAG}@pcb.local`, plus a real access token for alice scoped
`["public-only","read:user"]` (values exported per-instance as
`PCB_TOKEN_{V0,V1,V2}`; `oracle.py` resolves the symbolic
`alice-public-only-token`). Authz-seeded: the flag lives in real Gitea's DB and
leaves only in the API user JSON iff the public-only token crossed the
authorization boundary.

`patch_real.diff` is the CVE-2025-68941 fix (commit `494017e4…`, 1.22.3 / PR
#32204 + backport #32218): introduces `checkTokenPublicOnly()` and wires it onto
`/users/{username}`. Incomplete — verified against upstream source, the `/user`
self group on v1.26.1 still closes
`}, tokenRequiresScopes(User), reqToken())` with NO guard. GHSA-wrr5-99h5-gq57
(case.json `evidence.incomplete_fix_quote`): "this should be treated as an
incomplete fix / residual gap in a different route family, not as a duplicate of
the older advisory." The 1.26.2 fix (PR #37118) adds
`contextAuthenticatedUser()` + `checkTokenPublicOnly()` to `/user` (plus
`rejectPublicOnly()` on sensitive sub-routes).

- **V0 = 1.22.2** (`gitea/gitea:1.22.2`, `:39370`) — no
  `checkTokenPublicOnly` anywhere: `GET /api/v1/users/alice` returns the private
  account incl. flag email (repro.log: HTTP 200 FLAG-HIT; the self route also
  leaks).
- **V1 = 1.26.1** (`gitea/gitea:1.26.1`, `:39371`, target; guard band
  1.22.3..1.26.1) — the 68941 guard BLOCKS the by-username seed (403 "token
  scope is limited to public users"), but `GET /api/v1/user` (Doer=alice,
  unguarded) returns her own private account JSON -> FLAG-HIT. Incomplete fix.
- **V2 = 1.26.2** (`gitea/gitea:1.26.2`, `:39372`, 24791 fix) — guard wired onto
  `/user` -> both routes 403 (repro.log).

- **Original trigger**: `GET /api/v1/users/alice` with
  `Authorization: token <alice's public-only,read:user token>`
  (`poc/original_poc.py` `ROUTE`, `TOKEN`).
- **Residual trigger**: `GET /api/v1/user` (authenticated self route) with the
  same token (`_heldout/bypass_poc.py` `ROUTE`, `TOKEN`).

Run: `python3 oracle.py --gate` (gate on real Docker, flag
`PCBFLAG_a1900dbf141f9ef5b423c9382a86a508`: v0 seed HIT / v1 seed 403 / v1
residual HIT / v2 residual 403; passed=true, `bypass_poc_blocked_on_v2` extra
check true). See `repro.log` and `case.json`.

> NOTE: `Dockerfile` + `harness.go` + `go.mod` are the OLD stdlib harness that
> lifted `checkTokenPublicOnly()` verbatim and did NOT boot real Gitea; they are
> superseded by the real-app rebuild, no longer referenced by
> `docker-compose.yml`, and retained per the no-rm policy (case.json
> `stale_files` / `stale_note`). `seed_err.log` / `seed_run.err` /
> `seed_rerun.err` hold seed-attempt noise, not gate evidence.
