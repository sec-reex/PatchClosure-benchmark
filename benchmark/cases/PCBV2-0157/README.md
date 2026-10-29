# object-path-cve-2021-23434

object-path — CVE-2020-15256 -> CVE-2021-23434 (Prototype-pollution string-only `__proto__` guard
bypassed by a non-string (array) key = type confusion, CWE-1321 / CWE-843).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real Node HTTP harness (`harness.mjs`, `node:http`) exposes `GET /probe?spec=<JSON>`. It drives the
REAL published npm `object-path` per version (installed via npm aliases `object-path-v0/-v1/-v2`,
0.11.4/0.11.5/0.11.6) — specifically `objectPath.withInheritedProps.set(target, spec, "unlocked")`
on a fresh target (the CVE requires the `includeInheritedProps` instance: only that instance walks
inherited props AND the `__proto__` guard is gated on that flag). Same sink in all three versions =
the core `set()` key-walk leaf assignment `obj[currentPath] = value`. A benign default-deny flag-gate
then reads the gate key `pcbUnlock` off a fresh unrelated `({})`: it inherits it only if the crafted
key made `set()` pollute the GLOBAL `Object.prototype` (pollution by addition), in which case the
planted `${PCB_FLAG}` is echoed in `gated_secret`. Harness deletes `Object.prototype.pcbUnlock` after
every probe so probes stay isolated.

- **V0 = object-path 0.11.4** (`:39821`) — NO `__proto__` guard in `set()` (pre-CVE-2020-15256) ->
  the seed string path pollutes `Object.prototype` -> flag.
- **V1 = object-path 0.11.5** (`:39822`, target) — carries the CVE-2020-15256 fix
  `if (options.includeInheritedProps && (currentPath === '__proto__' || ...)) throw` — a strict
  `===` STRING comparison with NO coercion -> the string seed is BLOCKED (throw), but a NON-string
  key of the dangerous name slips it -> the CVE-2021-23434 residual still pollutes. Incomplete fix.
- **V2 = object-path 0.11.6** (`:39823`, -23434 fix) — inserts
  `if (typeof currentPath !== 'string' && typeof currentPath !== 'number') currentPath = String(currentPath)`
  BEFORE the guard -> the array key is coerced to `"__proto__"` and caught (throw) -> residual BLOCKED.

Benign shadow-class channel: no gadget chain, no code execution. The canary fires only on GLOBAL
prototype pollution BY ADDITION flipping a default-deny gate (`Object.prototype.pcbUnlock` absent =>
denied); a legitimate own-property write on the fresh target never trips it.

- **Original trigger**: `GET /probe?spec=["__proto__","pcbUnlock"]` — plain STRING segments; on V1
  `currentPath === '__proto__'` is true and `set()` throws
  ("For security reasons, object's magic properties cannot be set").
- **Residual trigger**: `GET /probe?spec=[["__proto__"],"pcbUnlock"]` — first segment is itself the
  ARRAY `["__proto__"]`; `["__proto__"] === '__proto__'` is FALSE so the V1 guard passes it, then
  `obj[currentPath]` stringifies the array back to `"__proto__"` (JS key `ToString`) and the walk
  steps onto `Object.prototype`; the leaf write lands `pcbUnlock` there -> flag.

Run: `PCB_FLAG=<token> python3 oracle.py --wait` (Variant A / `validate_case`; see `repro.log` for the
full V0/V1/V2 x seed/residual probe matrix and `case.json`).

Verified matrix (`repro.log`): V0{seed:POLLUTE, residual:POLLUTE} / V1{seed:BLOCK, residual:POLLUTE}
/ V2{seed:BLOCK, residual:BLOCK}; distinct fix commits 8e77521 (0.11.5) vs 43af2d8 (0.11.6).
