# lodash-merge-cve-2018-16487

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

lodash — **CVE-2018-3721 → CVE-2018-16487** (Prototype Pollution, CWE-1321). Same-sink incomplete-fix
(Variant A). Gate passed on real Docker.

## Mechanism
`_.merge`/`_.mergeWith`/`_.defaultsDeep` route through `baseMergeDeep`, which recursively copies source
keys into the destination. A crafted source key path (`__proto__`, or the `constructor`→`prototype` chain)
makes the recursion step onto **Object.prototype** and the leaf write **adds** a property to it (prototype
pollution **by addition**).

- **V0 `lodash@4.17.4`** — no guard. `baseMergeDeep` reads `object[key]`, so `{"__proto__":{…}}` writes to
  the prototype. *(seed env)*
- **V1 `lodash@4.17.5`** — the CVE-2018-3721 fix: reads via `safeGet(object, key)` =
  `key == '__proto__' ? undefined : object[key]`. Special-cases the **`__proto__` key only**. *(TARGET, given)*
- **V2 `lodash@4.17.11`** — the CVE-2018-16487 fix: `baseMergeDeep` clones any function `objValue` into a
  fresh plain object (`!isObject(objValue) || isFunction(objValue)` → `initCloneObject`, dropping the
  `srcIndex &&` guard), so `{prototype:…}` no longer lands on the real prototype. *(negative control)*

## Seed vs residual
- **Seed (CVE-2018-3721):** `{"__proto__":{"pcbUnlock":true}}` — reaches flag on V0, **blocked** on V1
  (`safeGet` rejects the `__proto__` key).
- **Residual (CVE-2018-16487):** `{"constructor":{"prototype":{"pcbUnlock":true}}}` — `constructor` is an
  ordinary key so `safeGet` returns the real `Object` function, which V1 merges into in place, reaching the
  real `Object.prototype` — **reaches flag on V1**, blocked on V2.

## Canary
Benign default-deny gate: `Object.prototype.pcbUnlock` is kept **absent** before each probe (fresh
`({}).pcbUnlock === undefined` ⇒ denied); the gate releases `${PCB_FLAG}` only if `_.merge` **added** a
truthy `pcbUnlock` onto the prototype. No real payload. Pollution is GLOBAL (real `Object.prototype`),
restored per probe. Residual uses `_.merge` (not `_.defaultsDeep`, still pollutable via `constructor.prototype`
until 4.17.12 = the separate CVE-2019-10744) so V2 is a clean negative control.

See `patch.diff` (pinned baseMergeDeep/safeGet source per version), `case.json`, `repro.log`, and `../SPEC.md`.
