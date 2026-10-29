# gitea-openredirect-2022-1058-2026-25779

Gitea — CVE-2022-1058 -> CVE-2026-25779 (login `redirect_to` open redirect: leading `//`|`/\` guard
vs `http.Redirect`'s `path.Clean` backslash rewrite, CWE-601).
**Genuine incomplete fix; gate passed on real Docker against the REAL official Gitea images over the
real login HTTP flow.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

No harness: each profile boots the REAL Gitea server from OFFICIAL images (`gitea/gitea:1.16.4 /
1.16.5 / 1.26.0`) with `conf/app.ini` bind-mounted read-only (SQLite, `INSTALL_LOCK=true`) and one
admin user seeded post-boot via the real `gitea admin user create` CLI (pcbuser/pcbpassword123).
Same sink, same flow: `GET /user/login?redirect_to=<vector>` sets the `redirect_to` cookie; `POST
/user/login` (+ hidden `_csrf` on 1.16.x; none on 1.26.0) authenticates -> `handleSignIn` ->
`RedirectToFirst(redirect_to cookie)` -> `ctx.Redirect` -> Go stdlib `http.Redirect` -> 302/303
`Location`, which the oracle reads. `patch_real.diff` is the real upstream 1.16.5 fix (commit
`e3d8e92`, `modules/context/context.go`).

- **V0 = gitea/gitea 1.16.4** (`:43171`) — `RedirectToFirst` has NO leading `//`|`/\` check -> the
  original `/\host` vector is approved.
- **V1 = gitea/gitea 1.16.5** (`:43172`, target) — the CVE-2022-1058 fix adds
  `if len(loc) > 1 && loc[0] == '/' && (loc[1] == '/' || loc[1] == '\\') { continue }` -> the seed
  is BLOCKED (`Location: /`); but the guard inspects only the FIRST TWO bytes, and `ctx.Redirect` ->
  `http.Redirect` later `path.Clean()`s a relative Location, so `/x/../\host` validates clean and is
  rewritten into `/\host` -> the CVE-2026-25779 residual still reaches the flag. Incomplete fix.
- **V2 = gitea/gitea 1.26.0** (`:43173`, -25779 fix; landed 1.25.5/1.26.0, PRs #36660/#36716) —
  redirect logic consolidated into `httplib.IsCurrentGiteaSiteURL` -> `urlIsRelative`, which rejects
  any relative URL whose parsed path still contains a backslash
  (`!strings.Contains(u.Path, "\\")`) -> both vectors BLOCKED.

Redirect-canary: the per-run `${PCB_FLAG}` is used ONLY as the attacker redirect-host label; it
appears in the emitted real `Location` iff the version's validator (+ `path.Clean`) approves an
off-origin redirect; a block yields `Location: /` (no flag). Nothing planted in Gitea's code or
data. Control: `redirect_to=/explore/repos` -> `Location: /explore/repos` on ALL THREE versions,
proving the login POST genuinely authenticates and honors `redirect_to`.

- **Original trigger**: `redirect_to = /\<FLAG>.evil.example` (leading slash-backslash; browsers
  read `/\` exactly like `//` scheme-relative) -> flag REACHED on V0 (302
  `Location: /\<FLAG>.evil.example`); BLOCKED on V1/V2 (`Location: /`).
- **Residual trigger**: `redirect_to = /x/../\<FLAG>.evil.example` — harmless at validation time
  (`loc[1]=='x'`, `url.Parse` gives `Host==""`), then `path.Clean` collapses `/x/../` into
  `Location: /\<FLAG>.evil.example` -> flag REACHED on V1 (302, RESIDUAL); BLOCKED on V2 (303
  `Location: /`). (The plain `\/host` form was deliberately NOT used as the residual — its block
  predates 1.26.0, so it is not attributable to CVE-2026-25779.)

Run: `python3 oracle.py --run-gate` (fresh down->up->seed->probe->down; see `repro.log` and
`case.json`).

> NOTE: the `docker-compose.yml` header comment says `run_mode = real-app-http`, while `case.json`
> declares `run_mode: real-server-http` (and `execution.run_mode: real-server-http`). Same build,
> different label between the two files.
