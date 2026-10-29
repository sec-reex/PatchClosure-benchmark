# pimcore-cve-2026-23492

Pimcore — CVE-2023-30848 -> CVE-2026-23492 (the 10.5.21 fix strips `--` from
`fields[]` and catches Doctrine `SyntaxErrorException` in the Admin Search Find
API, but a COMMENT-FREE injection keeps the statement syntactically valid — error
1105 is not a 1064 — so the raw object-brick key `$ob` still concatenates into the
JOIN clause; SQL injection, CWE-89). **Genuine incomplete fix; gate passed on real
Docker over EXTERNAL HTTP.**

不完整修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Pimcore from published Packagist pins (whole `pimcore/pimcore` via composer
+ `pimcore-install` + Apache/PHP + MySQL 8.0): V0 = 10.5.20 (pre-30848),
V1 = 10.5.21 (30848 fix, 23492 open — TARGET), V2 = 11.5.14 (23492 fix). The
oracle authenticates as the seeded Pimcore admin and hits the product's own Admin
Search Find endpoint (`/admin/search/search/find` on 10.5, moved to
`/admin/bundle/search/search/find` under the 11.5 SimpleBackendSearchBundle); a
testclass with a `bundledata` object-brick is seeded. Read-exfil canary:
`pcb_secret.flag` (= `${PCB_FLAG}`) is seeded from the environment at DB init and
never returned by a benign search; error-based `extractvalue` leaks it via the
MySQL XPATH error message echoed in the JSON error response.

`patch_real.diff` is the CVE-2023-30848 fix (commit
`25ad8674886f2b938243cbe13e33e204a2e35cc3`, 10.5.21 / #14972): `str_replace('--',
'', $fields)` + `catch (SyntaxErrorException) { throw ... 'Check your arguments.' }`.
GHSA-qvr7-7g55-69xj (case.json `evidence.incomplete_fix_quote`): "Although
CVE-2023-30848 attempted to mitigate SQL injection by removing SQL comments (--)
and catching syntax errors, the fix is insufficient... SQL injection does not
require SQL comments." The v11.5.14 fix validates each brick key with
`Objectbrick\Definition::getByKey($ob)`.

- **V0 = 10.5.20** (`:39493`) — no guard: the `-- ` comment payload closes the
  injected sub-select and comments out the code's own JOIN tail -> error-based
  `extractvalue` leaks the flag (repro.log: flag@V0 via XPATH 1105).
- **V1 = 10.5.21** (`:39494`, target) — the 30848 fix BLOCKS the comment seed
  (`--` stripped -> dangling tail -> 1064 caught -> "Check your arguments"), but
  the comment-free residual (JOIN tail target `object_brick_query_bundledata` on
  10.5, which appends `.o_id`) parses cleanly -> 1105 not caught -> flag.
  Incomplete fix.
- **V2 = 11.5.14** (`:39495`, 23492 fix) — brick-key whitelist rejects the
  crafted `$ob` -> "Check your object brick filter arguments" (repro.log;
  the 11.5 residual's JOIN tail target is `object_relations`, which appends `.id`).

- **Original trigger**: authenticated `fields[] =
"bundledata___CID__ b ON 1=1 JOIN (SELECT extractvalue(1,concat(0x7e,(SELECT flag
FROM pcb_secret LIMIT 1))) id2) c ON 1=1) ) -- ~x"` with the testclass filter
  (`poc/original_poc.py` candidate; `__CID__` substituted at runtime).
- **Residual trigger**: comment-free
  `fields[] = "bundledata___CID__ b ON 1=1 JOIN (SELECT extractvalue(...)) c ON
1=1 JOIN object_brick_query_bundledata~x"` (v1 target; `_heldout/bypass_poc.py`
  candidate, `_JOIN_TARGETS`). Control: benign search returns
  `{data:[], success:true}`.

Run: `PCB_FLAG=<tok> python3 oracle.py --wait --v2` (gate, rebuilt 2026-08-01
with real versions: v0 leaks / v1 blocks seed / v1 leaks residual / v2 blocks
residual; passed=true). See `repro.log` and `case.json`.

> NOTE: the root `entrypoint.sh` (php:8.2-cli + `harness/` "faithful-core" image)
> and this README's earlier stub text describe the PRE-REBUILD harness; per
> case.json `provenance.notes` the case was REBUILT 2026-08-01 so that all three
> profiles run REAL published Pimcore (the compose now builds
> `Dockerfile.pimcore10` / `Dockerfile.pimcore`). The stale faithful-core files
> were preserved per the NO-rm policy.
