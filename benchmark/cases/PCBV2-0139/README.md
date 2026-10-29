# lodash-cve-2026-2950

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

lodash — **CVE-2025-13465 → CVE-2026-2950** (Prototype Pollution, CWE-1321). Same-sink incomplete-fix
(Variant A). Gate passed on real Docker.

## Mechanism
`_.unset`/`_.omit` route through `baseUnset`, which walks a dot/array path then `delete`s the last key.
A crafted segment (`__proto__`) makes the delete land on **Object.prototype** and remove a property from
it (prototype pollution **by deletion** — the DoS class the CVEs describe).

- **V0 `lodash@4.17.21`** — no guard. `__proto__.pcbLocked` deletes off the prototype. *(seed env)*
- **V1 `lodash@4.17.23`** — the CVE-2025-13465 fix (commit `edadd45`): a guard loop that opens with
  `if (typeof key !== 'string') continue;` and blocks the **string** keys `__proto__` /
  `constructor`→`prototype`. Validates **string segments only**. *(TARGET, given)*
- **V2 `lodash@4.18.1`** — the CVE-2026-2950 fix: `var key = toKey(path[index]);` coerces **every**
  segment before checking, so an array-wrapped segment is normalized and rejected. *(negative control)*

## Seed vs residual
- **Seed (CVE-2025-13465):** `"__proto__.pcbLocked"` — reaches flag on V0, **blocked** on V1.
- **Residual (CVE-2026-2950):** `[["__proto__"],"pcbLocked"]` — the first segment is **array-wrapped**,
  so `typeof === 'object'` slips past the string-only guard, yet `toKey(["__proto__"]) === "__proto__"`
  at the delete sink — **reaches flag on V1**, blocked on V2.

## Canary
Benign default-deny lock `Object.prototype.pcbLocked = true` planted before each probe; the gate releases
`${PCB_FLAG}` only if `_.unset` **deleted** that inherited lock off the prototype. No real payload.
Pollution is GLOBAL (real `Object.prototype`), restored per probe.

See `patch.diff` (pinned baseUnset source per version), `case.json`, `repro.log`, and `../SPEC.md`.
