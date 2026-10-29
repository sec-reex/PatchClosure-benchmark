# locutus-cve-2026-33994

locutus (npm, PHP stdlib port) — CVE-2026-25521 -> CVE-2026-33994 (the 2.0.39 fix
only swaps the `parse_str` guard's detection method from
`String.prototype.includes` to `RegExp.prototype.test` — BOTH writable built-ins —
so overriding `RegExp.prototype.test` bypasses the new guard exactly as overriding
`String.prototype.includes` bypassed the old one; prototype pollution, CWE-1321).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Faithful-core: `node:20-slim` runs the REAL published `parse_str` bytes per
version (npm aliases `locutus@2.0.38` / `2.0.39` / `3.0.25`) behind a minimal
HTTP service (`GET /probe?override=..&qs=..`). Benign prototype-pollution
canary: polluting `Object.prototype.pcbUnlock` flips a default-deny
authorization gate that releases the planted `${PCB_FLAG}` as `gated_secret` —
no real payload. Per the advisory's stated chaining precondition
(case.json `flag.attack_model`), the harness models the upstream gadget by
overriding the NAMED built-in ONLY around the single `parse_str` call (each
version uses its guard method at most once in that file, verified against
source), so the sole thing under test is whether the version's guard survives
the override.

`patch_real.diff` is the CVE-2026-25521 fix (commit
`042af9ca7fde2ff599120783e720a17f335bb01c`, 2.0.39,
`src/php/strings/parse_str.js`): `key.includes(...)` ->
`/__proto__|constructor|prototype/.test(key)`. case.json
`evidence.incomplete_fix_quote`: "RegExp.prototype.test is itself a writable
prototype method that can be overridden, making the new guard bypassable in the
same way as the original — trading one hijackable built-in for another." The
3.0.25 fix (commit `345a6211e1` / PR #597) uses
`DANGEROUS_PARSE_STR_KEYS.has(key)` — Set strict-equality per parsed segment at
assignment time, no overridable method in the path.

- **V0 = 2.0.38** (`:39573`) — with `String.prototype.includes` overridden,
  qs `constructor[prototype][pcbUnlock]=1` walks to the assignment sink ->
  `Object.prototype.pcbUnlock` polluted -> gate releases the flag (repro.log:
  REACHES FLAG).
- **V1 = 2.0.39** (`:39574`, target) — the 25521 fix BLOCKS the includes-override
  seed (real `.test` matches "constructor" -> loop breaks), but with
  `RegExp.prototype.test` overridden, qs `__proto__[pcbUnlock]=1` passes the
  guard -> pollution -> flag. Incomplete fix.
- **V2 = 3.0.25** (`:39575`, 33994 fix) — `Set.has` guard; the test override is
  inert, key rejected -> blocked (repro.log: `_residual_blocked_on_v2`).

- **Original trigger**: `GET /probe?override=string-includes&qs=constructor[prototype][pcbUnlock]=1`
  (`poc/original_poc.py` candidate).
- **Residual trigger**: `GET /probe?override=regexp-test&qs=__proto__[pcbUnlock]=1`
  (`_heldout/bypass_poc.py` candidate).

Run: `PCB_FLAG=<tok> python3 oracle.py --wait` (gate 2026-07-11, flag
`PCBFLAG_81ace9606ad770d730db17aeeb1117a1`: seed reaches@v0 / blocked@v1 /
residual reaches@v1 / residual blocked@v2; passed=true). See `repro.log` and
`case.json`.

> NOTE: case.json `root_cause_note` records that the original task brief guessed
> RCE via an eval-like sink, but authoritative NVD + GHSA (GHSA-rxrv-835q-v5mh /
> GHSA-vc8f-x9pp-wf5p) show the actual root cause is prototype pollution — the
> class label differs from the brief; the incomplete-fix lineage itself is
> genuine.
