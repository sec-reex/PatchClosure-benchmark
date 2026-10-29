# pp2-convict

convict (mozilla node-convict) — CVE-2022-22143 -> CVE-2022-21190 (prototype pollution in
`config.set()`'s dotted-path deep-set; the 6.2.2 fix is a `startsWith('__proto__.')` prefix guard
bypassed by a prepended segment; CWE-1321).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real-app-http: each profile npm-installs the REAL published `convict` release
(6.2.1 / 6.2.2 / 6.2.3) with `express@4.21.2` on `node:18-slim` and boots a REAL Express service
(`app/server.js`, container port 8080). `POST /set {path,value}` hands the attacker JSON straight
to the real `config.set(req.body.path, req.body.value)` — convict splits the path on `.`, pops
the leaf, and `walk(this._instance, parentKey, true)` dereferences each segment with `obj = obj[k]`
(creating missing namespaces); a `__proto__` segment steps the walk ONTO the shared
Object.prototype and the leaf write pollutes it process-wide. `GET /check` reads a fresh object's
inherited `pcbUnlock` and releases `${PCB_FLAG}` iff present — a default-deny authorization gate
flipped open by pollution-by-addition. Pollution persists for the life of the node process, so the
oracle RESTARTS the target container (fresh process => clean Object.prototype) between probes and
versions. No in-process probe, no source-lift.

- **V0 = convict 6.2.1** (`:39851`) — `set()` carries only the weak exact-parentKey guard
  (`parentKey == '__proto__' || 'constructor' || 'prototype'`); the deep 3-segment seed's
  parentKey `__proto__.pcbUnlock` is NOT an exact match -> walk pollutes Object.prototype -> flag.
- **V1 = convict 6.2.2** (`:39852`, target) — CVE-2022-22143 fix replaces it with
  `FORBIDDEN_KEY_PATHS = ['__proto__', 'this.constructor.prototype']` +
  `if (k.startsWith(`${p}.`)) return this;` -> the seed (starts with `__proto__.`) is silently
  dropped, BLOCKED. But the prefix guard only inspects the START of the key -> a PREPENDED
  `foo.__proto__.pcbUnlock` slips past, `walk` creates `foo`, follows `foo.__proto__`
  (= Object.prototype) and writes `pcbUnlock` onto it -> the CVE-2022-21190 residual still
  pollutes. Incomplete fix.
- **V2 = convict 6.2.3** (`:39853`, -21190 fix) — each forbidden path gets a TRAILING dot
  (`['__proto__.']`) and the guard becomes
  `k.startsWith(forbidden_key_path) || k.includes(`.${forbidden_key_path}`)` — the dangerous
  segment is caught ANYWHERE in the path -> residual BLOCKED.

Flag channel: `PCB_FLAG` is injected via compose env; `GET /check` returns
`{"polluted": "<flag>"}` iff a fresh object inherits `pcbUnlock` from the polluted
Object.prototype, else `{"polluted": null}`. Note convict's guard does `return this` (silent
early-return, no throw), so `POST /set` responds `ok:true` even when the write is suppressed —
the BLOCK is observed on the `/check` differential channel. Benign canary only: pollution by
addition flipping a default-deny gate; no command execution.

- **Original trigger**: `POST /set {"path": "__proto__.pcbUnlock.x", "value": "unlocked"}` —
  parentKey `__proto__.pcbUnlock` clears V0's exact-match guard and pollutes (flag); on V1
  `'__proto__.pcbUnlock.x'.startsWith('__proto__.')` returns early, `/check` stays null (BLOCKED).
- **Residual trigger**: `POST /set {"path": "foo.__proto__.pcbUnlock", "value": "unlocked"}` —
  prepended benign segment `foo.` means the key does NOT start with `__proto__.`, so V1's prefix
  guard is silent while the walk still lands on Object.prototype (flag = CVE-2022-21190 bypass);
  V2's `includes('.__proto__.')` catches it (BLOCKED).

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.

> NOTE: like PCBV2-0042, the two diffs cover different fix generations — `patch_real.diff` is the
> V0->V1 CVE-2022-22143 fix (6.2.1..6.2.2, header says "CVE: CVE-UNKNOWN"; it replaces the weak
> exact-parentKey guard with the FORBIDDEN_KEY_PATHS `startsWith` prefix guard), while
> `patch.diff` is the V1->V2 CVE-2022-21190 fix (6.2.2 -> 6.2.3, trailing-dot +
> `includes('.__proto__.')`).
