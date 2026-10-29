# pp2-deep-get-set

deep-get-set — CVE-2020-7715 -> CVE-2022-21231 (prototype pollution in the `set()` key-walk, fixed by
a string-only guard bypassed via a non-string key; CWE-1321, residual = CWE-843 type confusion).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (repro.log: "Gate passed on
real Docker 2026-07-15"; Snyk: CVE-2022-21231 "derives from an incomplete fix of CVE-2020-7715").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`node:18-slim`, `app/server.js`) npm-installs the REAL published
`deep-get-set@<DGS_VER>` (+ `express@4.21.2`) — no source lift. `POST /set {path,value}` calls the
REAL published `deep({}, path, value)` set form on attacker JSON (the sink); pollution persists
PROCESS-WIDE, so the oracle RESTARTS the target container (fresh node process => clean
`Object.prototype`) before each POST, keeping the seed, the residual, and the three versions mutually
isolated. Same sink, same `deep()` set form; the advisory calls CVE-2022-21231 "an incomplete fix of
CVE-2020-7715".

- **V0 = deep-get-set 1.1.0** (`:39861`) — `set()` has NO magic-property guard; the walk dereferences
  each segment natively (`obj = obj[key]`) -> the string `__proto__` seed steps onto
  `Object.prototype` and the leaf write adds `isAdmin=true` -> seed reaches the flag.
- **V1 = deep-get-set 1.1.1** (`:39862`, target) — CVE-2020-7715 fix adds
  `isSafeKey(key) { return key !== '__proto__' && key !== 'prototype' && key !== 'constructor'; }`
  and `if (!isSafeKey(key)) return;` in the set() loop — a strict `!==` STRING comparison with NO
  coercion -> the all-string seed is BLOCKED (silent return, `POST /set` still answers `ok:true` but
  `/check` stays `null`), while the nested-array first segment `["__proto__"]` is
  `!== '__proto__'` so it slips the guard, yet `obj[key]` ToPropertyKey-coerces the array back to the
  string `'__proto__'` -> the CVE-2022-21231 residual still pollutes. Incomplete fix.
- **V2 = deep-get-set 1.1.2** (`:39863`, CVE-2022-21231 fix) — `isSafeKey` replaced by array-aware
  `isUnsafeKey` where `(Array.isArray(key) && key[0] === '__proto__')` is matched FIRST -> residual
  BLOCKED (and the seed too: clean negative controls). Dual ESM/CJS package; `require()` resolves
  `index.cjs`.

Benign default-deny authz gate: `Object.prototype.isAdmin` is ABSENT on a fresh process; `GET /check`
releases `${PCB_FLAG}` as `polluted` iff a prior `POST /set` caused the REAL `deep()` to ADD a truthy
`isAdmin` onto `Object.prototype` (pollution by addition, a default-deny authorization gate flipped
open). No gadget, no command execution; the flag token substring in the `/check` body is the only
oracle.

- **Original trigger**: `POST /set {"path": ["__proto__","isAdmin"], "value": true}` — all-STRING
  `__proto__` walk (V1 `isSafeKey('__proto__')` false -> early `return`).
- **Residual trigger**: `POST /set {"path": [["__proto__"],"isAdmin"], "value": true}` — the
  dangerous key is the ARRAY `["__proto__"]`; `[\"__proto__\"] !== '__proto__'` passes the V1 guard,
  then `obj[["__proto__"]]` stringifies to `'__proto__'` (CVE-2022-21231; advisory PoC
  `deep({}, [["__proto__"], 'polluted'], 'success')`).

Gate (repro.log, FLAG=`PCBFLAG_...`): original@v0 reaches (`/check polluted=<FLAG>`),
original@v1 blocked (`polluted:null`), bypass@v1 reaches (`polluted=<FLAG>` = residual), v2 blocks
BOTH seed and residual (`polluted:null`). Guard rejections are silent early returns, so `/set` stays
`ok:true` throughout — the differential is entirely in whether `Object.prototype` was polluted.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.
