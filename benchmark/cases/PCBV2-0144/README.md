# minimist-cve-2021-44906

minimist (npm CLI argument parser) — CVE-2020-7598 → CVE-2021-44906 (prototype pollution via the
`setKey()` key-path guard, CWE-1321).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

node:20-slim HTTP harness (`harness.mjs`) exposes `GET /probe?spec=<JSON argv>` and invokes the REAL
published npm bytes — minimist@1.2.1/1.2.5/1.2.6 installed side-by-side via npm aliases
(harness.mjs:59, `require("minimist-v0"|"minimist-v1"|"minimist-v2")`) — so the guard under test is
the version's actual `setKey()`. In front of it sits a benign default-deny flag-gate: `pcbUnlock` is
absent from `Object.prototype` (re-deleted before AND after every probe), and the planted
`${PCB_FLAG}` is returned as `gated_secret` only if the crafted parse polluted the SHARED prototype
(state-write by addition; a normal parse sets only own keys on its own result). No offensive payload.

- **V0 = minimist 1.2.1** (`:39831`) — `setKey()` has NO `__proto__` handling at all → the plain
  `__proto__` seed steps onto `Object.prototype` and the leaf write pollutes it → flag.
- **V1 = minimist 1.2.5** (`:39832`, target) — the CVE-2020-7598 guard
  `if (key === '__proto__') return;` (byte-identical in 1.2.3/1.2.4/1.2.5) BLOCKS the string seed,
  but it never inspects `constructor` → the `constructor.prototype` chain still reaches
  `Object.prototype`. Incomplete fix.
- **V2 = minimist 1.2.6** (`:39833`, CVE-2021-44906 fix) — `isConstructorOrProto(o, key)`
  (`key === 'constructor' && typeof o[key] === 'function' || key === '__proto__'`) catches the
  `constructor` segment → residual BLOCKED.

Why the residual works on V1: `--constructor.prototype.pcbUnlock.x` splits into
`['constructor','prototype','pcbUnlock','x']`; the walk resolves `constructor` → the Object function,
`prototype` → `Object.prototype`. The intermediate reference-reassignment `o['prototype'] = {}`
silently NO-OPs (`Object.prototype` is a non-writable property of `Object`), and because `prototype`
is an INTERMEDIATE segment the last-key `if (o === Object.prototype) o = {}` guard never fires, so
`pcbUnlock` is written onto the shared prototype.

- **Original trigger**: argv `["--__proto__.pcbUnlock","unlocked"]` → `setKey` keys
  `['__proto__','pcbUnlock']`, first segment is the literal string `'__proto__'`.
- **Residual trigger**: argv `["--constructor.prototype.pcbUnlock.x","unlocked"]` → keys
  `['constructor','prototype','pcbUnlock','x']`; not one segment equals `'__proto__'`, so the V1
  guard never returns.

Run: `PCB_FLAG=... python3 oracle.py --gate` (profiles v0/v1/v2; `--wait` first). See `repro.log`,
`case.json`, `docker-compose.yml`. Gate evidence (repro.log): seed FLAG@v0 / denied@v1 / denied@v2;
residual FLAG@v0 / FLAG@v1 / denied@v2 — all six cells verified on real Docker.

> NOTE: `patch.diff` (listed in `case.json` `given_to_method`) is actually the V2/CVE-2021-44906 fix
> (minimist 1.2.6, commit 7efb22a5, `isConstructorOrProto`), while `patch_real.diff` carries the
> CVE-2020-7598-era upstream fix commit 63e7ed05 whose diff adds the reference check
> `if (o[key] === {}.__proto__) o[key] = {};`. Per `case.json.source_verified_caveat` and
> `repro.log` ("VERSION PINS"), that reference check is the 1.2.2 PARTIAL hardening — the very
> reason V0 was re-pinned from 1.2.2 to 1.2.1 — and the guard actually present in V1 (1.2.5) is the
> string check `if (key === '__proto__') return;` introduced in 1.2.3. The guard-vs-version mapping
> above follows case.json/repro.log (verified against the real tarballs); `patch_real.diff`'s header
> attribution of 63e7ed05 as "the CVE-2020-7598 fix" does not match that mapping.
