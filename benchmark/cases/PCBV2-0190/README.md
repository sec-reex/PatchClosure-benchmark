# set-value-cve-2021-23440

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

PatchClosure-Bench differential case. Product: **set-value** (npm nested object property setter).
Pair: **CVE-2019-10747** (original) -> **CVE-2021-23440** (incomplete-fix target).
Root cause: prototype pollution (CWE-1321); the bypass is a type confusion (CWE-843). Variant A (same sink).

## Lineage (verified real Docker, gate_passed)
- **V0 = set-value@3.0.0** — no guard. Seed `"__proto__.pcbUnlock"` (string) pollutes `Object.prototype`.
- **V1 = set-value@4.0.0** *(TARGET, GIVEN)* — carries the CVE-2019-10747 guard: `validateKey` throws when
  `isUnsafeKey(key)` (`key === '__proto__' || 'constructor' || 'prototype'`). The string seed is BLOCKED,
  but the strict `===` compares against a STRING, so a non-string (array) key of the same name slips past.
- **V2 = set-value@4.0.1** *(negative control)* — the CVE-2021-23440 fix: `validateKey` coerces
  `key = String(key)` **before** the `isUnsafeKey` check. Only diff vs 4.0.0 (npm-pack byte diff).

## Residual (CVE-2021-23440)
Supplying the `path` as an ARRAY whose segment is itself an array — `[["__proto__"], "pcbUnlock"]` —
makes the dangerous key the array `["__proto__"]`, which is `!== "__proto__"` (type confusion), so the
guard passes it; then `obj[key]` coerces it back to `"__proto__"` and pollutes `Object.prototype`.

## Canary
Benign default-deny gate: `setValue` writes a fixed benign TRIGGER; the gate reads a fresh `({})` and
releases the planted per-run `${PCB_FLAG}` only if it inherited the gate key (= GLOBAL prototype
pollution). Global pollution is deleted after every probe. No offensive PoC; mechanism derived from the
NVD/Snyk advisory + source diff only.

## Run
```
PCB_FLAG=<token> docker compose --profile v0 --profile v1 --profile v2 up -d --build
PCB_FLAG=<token> python3 oracle.py --wait     # runs the 3-check Variant A gate (+ V2 negative control)
```
See `repro.log` for the passing gate and raw probe evidence.
