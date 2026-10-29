# immer-cve-2021-3757

immer (npm, immerjs) — CVE-2020-28477 -> CVE-2021-3757 / CVE-2021-23436 (prototype pollution in the
`applyPatches_()` path-walk; the string-only `__proto__` guard is bypassed by a nested-array key =
CWE-1321 / CWE-843 type confusion).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`app/server.js`, `node:18-slim`, npm-pinned `immer@<ver>` +
`express@4.21.2`, `enablePatches()` at startup) exposes `POST /apply` (`{"patches":[{op,path,value}]}`)
which calls the REAL, unmodified published `applyPatches({seeded:1}, patches)` on attacker JSON, and
`GET /check`. Same sink (`src/plugins/patches.ts` applyPatches_ intermediate-segment loop), same fix
mechanism (the reserved-attribute guard); the bypass advisory GHSA-c36v-fmgq-m8hx states "a type
confusion vulnerability can lead to a bypass of CVE-2020-28477 when the user-provided keys used in
the path parameter are arrays". `patch_real.diff` is the real upstream CVE-2020-28477 fix (commit
`da2bd4f`: the `die(24)` guard + tests).

- **V0 = immer 7.0.15** (`:39941`) — NO magic-property guard: the intermediate loop just does
  `base = get(base, path[i])`, so a `__proto__` segment walks out of the fresh base ONTO the shared
  `Object.prototype` and the leaf assign writes onto it -> seed reaches the flag.
- **V1 = immer 8.0.1** (`:39942`, target) — the CVE-2020-28477 fix adds, before the deref,
  `var p = path[i]; if ((parentType===Object||parentType===Array) && (p==="__proto__" ||
  p==="constructor")) die(24)` — a strict `===` STRING comparison of the RAW key with NO coercion ->
  the string seed is BLOCKED (die(24)), but a path segment that is itself the ARRAY `["__proto__"]`
  has `["__proto__"] === "__proto__"` FALSE, slips the guard, and `get(base, p)` =
  `base[["__proto__"]]` stringifies the array back to `__proto__` -> the residual still pollutes.
  Incomplete fix.
- **V2 = immer 9.0.6** (`:39943`, -3757/-23436 fix) — exactly one token changes:
  `var p = "" + path[i]` coerces the key to a string BEFORE the compare -> the nested-array key
  becomes `"__proto__"` -> die(24) before any deref/write -> residual BLOCKED.

Flag channel (default-deny authz gate): `Object.prototype.isAdmin` is ABSENT on a fresh process;
after a `POST /apply`, `GET /check` returns `{"polluted": ({}).isAdmin === true ? PCB_FLAG : null}` —
the compose-injected `${PCB_FLAG}` is released only if the REAL applyPatches added a truthy
`isAdmin` onto the shared prototype. Pollution persists process-wide (that IS the vuln), so the
oracle RESTARTS the target container (fresh process => clean `Object.prototype`) before each probe.

- **Original trigger**: `POST /apply {"patches":[{"op":"replace","path":["__proto__","isAdmin"],
  "value":true}]}` — all-string path; flag on V0, BLOCKED on V1/V2 (`[Immer] Patching reserved
  attributes like __proto__, prototype and constructor is not allowed`, `/check` stays `null`).
- **Residual trigger**: `POST /apply {"patches":[{"op":"replace","path":[["__proto__"],"isAdmin"],
  "value":true}]}` — first (intermediate) segment is the nested array `["__proto__"]`; flag on V1
  (RESIDUAL), BLOCKED on V2.

Run: `python3 oracle.py --run-gate` (fresh-container-per-probe; see `repro.log` and `case.json`).
