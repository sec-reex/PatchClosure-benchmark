# parse-server-literalizeRegexPart-pg-sqli

Parse Server — CVE-2024-27298 -> CVE-2024-39309 (PostgreSQL `$regex` SQL injection via
`literalizeRegexPart` single-quote escaping, CWE-89).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL npm `parse-server` (6.4.0 / 6.5.0 / 6.5.7, installed at build time on `node:18-bookworm-slim`
— the official `parseplatform/parse-server` images have no 6.4.0/6.5.0 tags) behind a thin
`app/server.js` Express host with zero canary logic, over an official `postgis/postgis:14-3.4`
sidecar. Canary is seeded from OUTSIDE via the Parse REST API with masterKey: an ACL-restricted
`Vault` row (`secret` = `${PCB_FLAG}`, `ACL:{}` => `_rperm=[]`) plus a public decoy row. The external
trigger is an anonymous
`GET /parse/classes/Vault?where={"name":{"$regex":<payload>}}` with only
`X-Parse-Application-Id`. Same sink in all three versions = `PostgresStorageAdapter` inserting the
escaped `$regex` RAW (pg-promise `:raw`) into `` <col> ~ '<pattern>' `` — the sink line is
byte-identical across 6.4.0/6.5.0/6.5.7; only `literalizeRegexPart`'s quote escaping changes. A
successful injection makes the WHERE always-true and comments out the `_rperm` ACL filter, so the
flag row comes back in `results` (flag token in the JSON body). Benign baseline: querying
`$regex=publicrow` returns only the decoy — the ACL genuinely defends the flag row.

- **V0 = parse-server 6.4.0** (`:39640` at gate time) — `.replace(/([^'])'/, "$1''")` WITHOUT `/g`:
  only the FIRST quote is doubled -> the seed's second quote breaks out of the `~ '<pattern>'`
  literal -> flag.
- **V1 = parse-server 6.5.0** (`:39650`, target) — CVE-2024-27298 fix (commit `cbefe770a726`,
  PR #8961, `patch.diff` = `patch_real.diff`) adds the `/g` flag -> SEPARATED quotes are both
  doubled -> the seed is BLOCKED (`results:[]`). But `/([^'])'/g` never matches a quote preceded by
  another quote: a RUN of consecutive quotes is doubled only on its first member, leaving ODD parity
  -> the CVE-2024-39309 residual still breaks out. Incomplete fix.
- **V2 = parse-server 6.5.7** (`:39657`, -39309 fix, commit `2edf1e4c0363`, PR #9167) — escaping
  replaced by `.replace(/'+/g, m => m.length % 2 === 0 ? m : m + "'")`: every quote-run normalised
  to EVEN length -> residual BLOCKED.

Captured SQL (Postgres `log_statement=all`, `repro.log`): on V1 the residual renders
`WHERE "name" ~ 'a''' OR 1=1 -- ' AND ("_rperm" ...)  LIMIT 100` — the `_rperm` filter is
commented out; the blocked seed renders a balanced literal with the filter intact.

- **Original trigger**: `$regex` = `a'b' OR 1=1 -- ` (two quotes SEPARATED by non-quotes); flag on
  V0, blocked on V1 and V2.
- **Residual trigger**: `$regex` = `a'' OR 1=1 -- ` (one EVEN run of two CONSECUTIVE quotes); V1's
  `/g` doubles only the first quote of the run (`a''` -> `a'''`, odd parity) -> dangling breakout
  quote -> flag on V1; blocked on V2.

Run: `PCB_FLAG=<tok> python3 oracle.py --seed --profiles v0 v1`, then `--gate` and `--v2check`
(Variant A + extended booleans). Verified (`repro.log`, gate 2026-07-13): seed FLAG@v0 / BLOCKED@v1;
residual FLAG@v1 / BLOCKED@v2; benign no-flag everywhere; distinct commits
`cbefe770a726` vs `2edf1e4c0363`, distinct fixed versions 6.5.0 vs 6.5.7 (GHSA-6927-3vr9-fxf2 /
GHSA-c2hr-cqg6-8j6r, same ZDI finder lineage ZDI-CAN-19105 -> ZDI-CAN-23894). See `case.json`.

> NOTE (port mapping): the committed `docker-compose.yml` hardcodes `ports: ["1337:1337"]` for all
> three profiles (and `scripts/start.sh` / `case.yaml` readiness use `:1337`, one profile up at a
> time), while `oracle.py` BASE and `case.json`/`repro.log` target
> `http://127.0.0.1:39640|39650|39657/parse`. The recorded gate run used the 3964x ports; as
> committed, the three profiles collide on host port 1337 and cannot be up simultaneously without a
> port override. → 已于 2026-10-11 修复：`docker-compose.yml` 三个 `parse_v*` 服务宿主端口参数化为
> `${PORT_V0_0:-39640}:1337` / `${PORT_V1_0:-39650}:1337` / `${PORT_V2_0:-39657}:1337`（容器端口仍 1337，
> `case.yaml` readiness/exposed_ports 按容器端口原样保留，平台与 verify.sh 仍经 `docker compose port`
> 动态解析宿主端口；`scripts/start.sh` 的就绪等待与播种改为使用解析出的宿主端口，回退与 compose 默认一致），
> 三 profile 可同时 up 无冲突，`oracle.py` 的 3964x 端口即默认宿主端口（`docker compose config`
> 三 profile 同开渲染 published 39640/39650/39657，2026-10-11 实测）。
>
> NOTE (fix-commit hash): `patch_real.diff`'s header cites CVE-2024-27298 fix commit
> `a6e654943536932904a69b51e513507fcf90a504`, while `case.json`/`patch.diff`/`repro.log` cite
> `cbefe770a726` (PR #8961) for the same fix. The diff body is the same one-line `/g` change in
> `literalizeRegexPart`; the header hash is unverified against the other artifacts.
