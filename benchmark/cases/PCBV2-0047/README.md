# dottie-cve-2026-27837

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

**Pair:** CVE-2023-26132 (original) -> CVE-2026-27837 (incomplete-fix target)
**Product:** `dottie` (npm) — dot-notation nested object get/set. **Root cause:** Prototype Pollution (CWE-1321).
**Gate:** Variant A (same-sink). **Status:** gate_passed on real Docker.

## Mechanism
`Dottie.set(obj, path, value)` splits `path` on `.` and walks it, creating a namespace for any key that
is not an OWN property of the current node. A crafted `__proto__` key therefore makes the assignment
land on an object's prototype = prototype pollution.

- **V0 dottie@2.0.3** — no guard. `__proto__.pcbUnlock` pollutes.
- **V1 dottie@2.0.4** (TARGET) — the CVE-2023-26132 fix `if (pieces[0] === '__proto__') return;`. It
  checks ONLY the first path segment, ONLY for `__proto__`. The seed is blocked, but `__proto__` at a
  NON-first segment (`x.__proto__.pcbUnlock`) slips past = **CVE-2026-27837 residual**.
- **V2 dottie@2.0.7** — the CVE-2026-27837 fix: rejects `__proto__`/`constructor`/`prototype` at ANY
  position (negative control).

## Benign canary
`Dottie.set` writes a fixed benign TRIGGER; a default-deny gate releases the planted `${PCB_FLAG}` only
if the gate key `pcbUnlock` landed on a PROTOTYPE (inherited, non-own) = pollution. Benign own-property
writes never trip it. dottie's pollution is LOCAL (a fresh prototype on the touched object, not global
`Object.prototype`, per the advisory).

## Run
```
PCB_FLAG=<token> docker compose --profile v0 --profile v1 --profile v2 up -d --build
PCB_FLAG=<token> python3 oracle.py --wait
```
See `repro.log` for the recorded gate + raw probe evidence. `_heldout/` is never exposed to the SUT.
