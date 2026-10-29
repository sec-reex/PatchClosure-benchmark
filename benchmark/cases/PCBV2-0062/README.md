# dset-cve-2024-21529

dset (npm `dset`, lukeed) — CVE-2022-25645 -> CVE-2024-21529 (Prototype pollution string-only key guard,
CWE-1321 / CWE-843).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core harness (`harness.mjs`, `node:20-slim`): one image, role selected by `HARNESS_VER`; the
three REAL published dset releases are installed side-by-side via npm aliases (`dset-v0` =
npm:dset@2.0.1, `dset-v1` = @3.1.2, `dset-v2` = @3.1.4) and the harness invokes the EXACT published
`dset()` bytes. `GET /probe?spec=<JSON>` runs the version's real `dset(freshTarget, spec, "unlocked")`,
then a benign default-deny flag-gate asks whether an UNRELATED fresh `({})` now inherits
`pcbUnlock === "unlocked"` — i.e. whether the crafted key made the write land on the shared
`Object.prototype` (prototype pollution BY ADDITION; a legitimate own-property write never trips it).
Pollution is GLOBAL, so the harness `delete Object.prototype.pcbUnlock` after every probe. Same sink
(the core `dset()` key-loop), same gate; Snyk SNYK-JS-DSET-7116691: "dset before 3.1.4 is vulnerable
to prototype pollution via the dset function".

- **V0 = dset 2.0.1** (`:39811`) — `dset()` has NO key guard (pre-3.0.0); the walk `t = t[k]` steps
  onto `Object.prototype` at the `__proto__` segment and the leaf writes `pcbUnlock` onto it -> seed
  pollutes and the gate releases the flag.
- **V1 = dset 3.1.2** (`:39812`, target) — the key-loop guard
  `if (k === '__proto__' || k === 'constructor' || k === 'prototype') break;` with `k = keys[i++]`
  (strict `===` against the STRINGS, NO coercion) -> the string seed breaks the loop before any write
  (BLOCKED), but the array-key residual makes the dangerous key the array `['__proto__']`;
  `['__proto__'] === '__proto__'` is FALSE so the guard passes it, then `t[k]` ToStrings the array
  back to `'__proto__'` and the walk still lands on `Object.prototype` -> the CVE-2024-21529 residual
  pollutes and the flag is released. Incomplete fix.
- **V2 = dset 3.1.4** (`:39813`, -21529 fix, commit `16d6154`) — the loop coerces
  `k = ''+keys[i++]` BEFORE the guard, so the array key becomes the string `'__proto__'` and is caught
  (break) -> residual BLOCKED (V2 also blocks the original; negative control).

- **Original trigger**: `spec = ["__proto__", "pcbUnlock"]` via `GET /probe` — plain STRING segments;
  on 3.1.2 the guard's `k === '__proto__'` fires and the loop breaks with no write.
- **Residual trigger**: `spec = [["__proto__"], "pcbUnlock"]` — an ARRAY path whose first segment is
  ITSELF an array (Snyk PoC `dset({}, [["__proto__"], "polluted"], true)` with the leaf key renamed to
  the gate key); the guard compares the raw key without coercing its type (CWE-843 type confusion),
  then property access coerces it to the dangerous name.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE (CVE-2022-25645 attribution, source-verified per `case.json.source_verified_caveat`): the
> core `dset()` string guard was first introduced in dset 3.0.0 (commit `0a11c8a`), NOT by
> CVE-2022-25645's 3.1.2 release — 3.1.2's fix (commit `2d156c7`) patched the SIBLING `dset/merge`
> helper's copy loop instead. dset@3.1.1/3.1.2/3.1.3 carry the byte-identical string-only `dset()`
> guard; V1 is pinned to 3.1.2 to match the CVE-2022-25645 fixed_version. The plain-string seed
> represents the CVE-2022-25645-class pollution (a `__proto__` segment through dset()) and is NOT
> claimed to be byte-for-byte 25645's `dset/merge` PoC.
