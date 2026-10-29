# pp2-json-ptr

json-ptr — CVE-2020-7766 -> CVE-2021-23509 (prototype pollution in `setValueAtPath`'s segment-walk,
fixed by a string-only segment guard bypassed via a non-string segment; CWE-1321, residual = CWE-843
type confusion). **Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP** (repro.log:
"VERDICT: gate_passed (gold)"; NVD on CVE-2021-23509: "A type confusion vulnerability can lead to a
bypass of CVE-2020-7766 when the user-provided keys used in the pointer parameter are arrays").

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`node:18-slim`, `app/server.js`) npm-installs the REAL published
`json-ptr@<JSONPTR_VER>` (+ `tslib@2`, `express@4.21.2`) — no source lift. `POST /set {pointer,value}`
calls the REAL published static `JsonPointer.set({}, pointer, value, true)` on attacker JSON (the
sink; `force=true` so missing intermediates are created and the leaf write fires — NVD for
CVE-2020-7766 says "when the force flag is set to true"). Pollution persists PROCESS-WIDE, so the
oracle RESTARTS the target container before each POST (fresh process => clean `Object.prototype`;
every pre-probe `/check` returned null in the recorded run). Same sink, same segment-walk hardened
across the three versions; the bypass is exactly the advisory's array-keys case.

- **V0 = json-ptr 1.3.0** (`:39881`) — `setValueAtPath` has NO magic-property guard; the walk
  dereferences each segment natively (`it = it[step]`) -> the string `__proto__` seed steps onto
  `Object.prototype` and the leaf write sets `isAdmin=true` -> seed reaches the flag.
- **V1 = json-ptr 2.0.0** (`:39882`, target) — CVE-2020-7766 fix adds, at the top of each
  `setValueAtPath` while-loop step,
  `if (step === '__proto__' || step === 'constructor' || step === 'prototype') throw new
  Error('Attempted prototype pollution disallowed.')` — a strict `===` STRING comparison of the RAW
  segment with NO coercion -> the all-string seed is BLOCKED (`POST /set` returns blocked, `/check`
  null), while the nested-array first segment `["__proto__"]` has
  `["__proto__"] === '__proto__'` FALSE so it slips the guard, yet `it = it[step]` coerces the array
  back to `'__proto__'` -> the CVE-2021-23509 residual still pollutes. Incomplete fix. (V1's
  `unsetValueAtPath` has no guard at all — analysis doc.)
- **V2 = json-ptr 3.0.0** (`:39883`, CVE-2021-23509 fix) — adds, BEFORE the string guard,
  `if (typeof step !== 'string' && typeof step !== 'number') throw new TypeError('PathSegments must be
  a string or a number.')` -> the nested-array segment (typeof `'object'`) is rejected before any
  deref/write; the string seed is still caught by the string guard. Both blocked.

Benign default-deny authz gate: `Object.prototype.isAdmin` is ABSENT on a fresh process; `GET /check`
releases `${PCB_FLAG}` as `polluted` iff a prior `POST /set` caused the REAL `JsonPointer.set()` to
ADD a truthy `isAdmin` onto `Object.prototype` (pollution by addition). No gadget, no command
execution; the flag token substring in the `/check` body is the only oracle.

- **Original trigger**: `POST /set {"pointer": ["__proto__","isAdmin"], "value": true}` — all-STRING
  `__proto__` walk (V1's string guard throws).
- **Residual trigger**: `POST /set {"pointer": [["__proto__"],"isAdmin"], "value": true}` — the
  dangerous segment is the ARRAY `["__proto__"]`; `=== '__proto__'` is false so the V1 guard passes
  it, then `it[step]` stringifies to `'__proto__'` (CVE-2021-23509; advisory PoC
  `JsonPointer.set({}, [['__proto__'], 'polluted'], 'success', true)`).

Gate (repro.log matrix, FLAG=`PCBFLAG_1f3f84bf10d143f2b093e6f5249f7ff6`): V0 seed AND residual both
pollute (`/check FLAG`); V1 seed blocked ("Attempted prototype pollution disallowed.") while V1
residual pollutes (`/check FLAG` = residual); V2 blocks both ("PathSegments must be a string or a
number." for the residual). run_mode=real-app-http; no in-process probe (curl only).

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.

Packaging note (from the Dockerfile): `json-ptr@1.3.0` ships compiled code that `require('tslib')`
but forgot to DECLARE it as a dependency (packaging bug), so `tslib@2` is installed explicitly in all
three images (2.0.0 declares `tslib@^2.0.3` itself; 3.0.0 needs none).
