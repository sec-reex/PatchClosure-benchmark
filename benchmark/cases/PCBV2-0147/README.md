# mongoose-cve-2025-23061

Mongoose (npm `mongoose`, Node.js MongoDB ODM) — CVE-2024-53900 -> CVE-2025-23061
(the 8.8.3 fix's `$where` guard in `getModelsMapForPopulate` is NON-recursive: it
inspects only each top-level array item's own `$where` key, so a `$where` nested
inside `$or`/`$and` slips past into sift's search injection; root_cause recorded
as `SQLi`, mechanism_family `nosql-injection`; case.json gives no CWE ID).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real published npm mongoose via aliases (`mongoose@8.8.2` = V0 / `8.8.3` = V1 /
`8.9.5` = V2, exact published bytes installed side-by-side in package.json) on
node:20-slim behind a real `mongo:7`; the guard is the per-version
`lib/helpers/populate/getModelsMapForPopulate.js` driven through the real Mongoose
API `Author.find().populate({path:'books', match:<filter>})`. Array-form match
routes the filter through sift IN THE NODE PROCESS (`assignVals` -> `sift(match)`,
whose `$where` compiles `new Function('return ' + expr)`); the benign predicate
`true` merely widens the populate match. Read-exfil canary: each version's db
seeds a protected `secret:true` Book titled `SECRET_BOOK::${PCB_FLAG}` referenced
by the author; the intended filter `{"secret":false}` excludes it at MongoDB, so
the flag appears in populated book titles only when the `$where` predicate widens
the match past the guard. No offensive payload is executed.

NVD (case.json `evidence.incomplete_fix_quote`): "Mongoose before 8.9.5 can
improperly use a nested $where filter with a populate() match, leading to search
injection. NOTE: this issue exists because of an incomplete fix for
CVE-2024-53900." `patch_real.diff` is the CVE-2024-53900 fix (commit
`c9e86bff…`, 8.8.3): the non-recursive `if (item != null && item.$where) throw`
loop for array matches. The CVE-2025-23061 fix (commit `64a9f970`, 8.9.5)
replaces it with a recursive `throwOn$where` that walks every nested key;
repro.log DQ confirms intervening 8.8.4/8.9.0-8.9.4 did not touch the check.

- **V0 = 8.8.2** (`:39595`) — no guard: filter `[{"$where":"true"}]` -> sift
  admits the secret book -> flag leaked (repro.log: LEAK FLAG).
- **V1 = 8.8.3** (`:39596`, target) — the 53900 guard BLOCKS the top-level seed
  ("Cannot use $where filter with populate() match"), but
  `[{"$or":[{"$where":"true"}]}]` has no own `$where` key at top level -> guard
  misses it -> sift evaluates the nested `$where` -> flag leaked. Incomplete fix.
- **V2 = 8.9.5** (`:39597`, 23061 fix) — recursive `throwOn$where` throws on both
  payloads (repro.log: BLOCKED on both).

- **Original trigger**: array-form populate match
  `[{"$where":"true"}]` (`poc/original_poc.py` candidate `filter`).
- **Residual trigger**: `[{"$or":[{"$where":"true"}]}]` (nested inside `$or`;
  `_heldout/bypass_poc.py` candidate `filter`). Control: `{"secret":false}`
  returns only the public book on all versions.

Run: `python3 oracle.py --wait --with-v2` (gate 2026-07-12 on real Docker:
seed reaches@v0 / seed blocked@v1 / residual reaches@v1 / residual blocked@v2;
passed=true). See `repro.log` and `case.json`.
