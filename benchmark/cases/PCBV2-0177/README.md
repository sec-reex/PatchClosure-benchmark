# pp2-set-in

set-in — CVE-2020-28273 -> CVE-2022-25354 (prototype pollution in `setIn()`'s key-walk, fixed by a
string-only `!== '__proto__'` assert bypassed via a non-string key; CWE-1321, residual = CWE-843 type
confusion). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (repro.log:
"Gate passed on real Docker 2026-07-15"; Snyk: CVE-2022-25354 "derives from an incomplete fix of
CVE-2020-28273").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`node:18-slim`, `app/server.js`) npm-installs the REAL published
`set-in@<SETIN_VER>` (+ `express@4.21.2`) — no source lift. `POST /merge {path,value}` calls the REAL
published `setIn({}, path, value)` on attacker JSON (the sink; the library requires an ARRAY path).
Pollution persists PROCESS-WIDE, so the oracle RESTARTS the target container before each POST (fresh
process => clean `Object.prototype`), keeping the seed, the residual, and the three versions mutually
isolated. Same sink, same key-walk hardened across the three versions; the advisory calls the bypass
an incomplete fix of the original.

- **V0 = set-in 2.0.0** (`:39871`) — `recursivelySetIn` has NO magic-property guard (`set()` is just
  `object[key] = value`); the walk dereferences each segment natively (`object = object[key]`) -> the
  string `__proto__` seed steps onto `Object.prototype` and the leaf write adds `isAdmin=true` ->
  seed reaches the flag.
- **V1 = set-in 2.0.1** (`:39872`, target) — CVE-2020-28273 fix adds, at the top of each
  `recursivelySetIn` level, `assert.ok(path[index] !== '__proto__', ...)` (plus a
  constructor/prototype pair assert) — a strict `!==` STRING comparison of the RAW key with NO
  coercion -> the all-string seed is BLOCKED (`merge blocked: setIn: "__proto__" is disallowed in
  path`, `/check` null), while the nested-array first segment `["__proto__"]` has
  `["__proto__"] !== '__proto__'` TRUE so the assert passes it, yet `object[key]` coerces the array
  back to `'__proto__'` -> the CVE-2022-25354 residual still pollutes. Incomplete fix. (The analysis
  doc also points out a decoy second guard in the same function: `if (key === '__proto__' || …) { }`
  with an EMPTY body.)
- **V2 = set-in 2.0.3** (`:39873`, CVE-2022-25354 fix) — adds, at `setIn()` entry,
  `assert.ok(path.every(p => typeof p === 'number' || typeof p === 'string'), ...)` -> the
  nested-array segment (typeof `'object'`) throws BEFORE any recursion/write -> residual BLOCKED
  (`merge blocked: setIn: expected array path (of strings and numbers)`, `/check` null).

Benign default-deny authz gate: `Object.prototype.isAdmin` is ABSENT on a fresh process; `GET /check`
releases `${PCB_FLAG}` as `polluted` iff a prior `POST /merge` caused the REAL `setIn()` to ADD a
truthy `isAdmin` onto `Object.prototype` (pollution by addition). No gadget, no command execution;
the flag token substring in the `/check` body is the only oracle.

- **Original trigger**: `POST /merge {"path": ["__proto__","isAdmin"], "value": true}` — all-STRING
  `__proto__` walk (V1's assert throws `"__proto__" is disallowed in path`).
- **Residual trigger**: `POST /merge {"path": [["__proto__"],"isAdmin"], "value": true}` — the
  dangerous key is the ARRAY `["__proto__"]`; `!== '__proto__'` passes the V1 assert, then
  `object[["__proto__"]]` stringifies to `'__proto__'` (CVE-2022-25354; advisory PoC
  `setIn({}, [['__proto__'],'polluted'], 'success')`).

Gate (repro.log, FLAG=`PCBFLAG_b267d23e61f0bcd28050d6475e29c071`): original@v0 reaches
(`/check polluted=<FLAG>`), original@v1 blocked, bypass@v1 reaches (`polluted=<FLAG>` = residual),
residual blocked on v2 (negative control).

> NOTE: on V2 the STRING seed is NOT cleanly blocked — repro.log records
> `original_blocked_on_v2 : false`: 2.0.3's leaf POLLUTED_KEYS assert throws only AFTER the inner
> leaf write already landed, so the v2 seed probe shows `merge blocked` yet `/check polluted=<FLAG>`
> (verbatim: `{"ok":false,"blocked":true,...}` / `{"polluted":"<FLAG>",...}`). The case.json
> `source_verified_caveat` and provenance mark this quirk INFORMATIONAL: the residual this case
> concerns IS cleanly blocked on V2, and the Variant-A gate does not depend on V2.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.
