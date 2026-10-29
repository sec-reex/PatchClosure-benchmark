# adonisjs-bodyparser-cve-2026-48795

Same-sink incomplete-fix pair on the **real** `@adonisjs/bodyparser` npm package.

- **Pair:** CVE-2026-25754 (V1 = incomplete-fix TARGET) → CVE-2026-48795 (V2 = complete fix)
- **Root cause:** prototype pollution (CWE-1321)
- **Sink:** `FormFields.add(key,value)` → `lodash.set(#fields, key, value)`, reached from
  `BodyParserMiddleware.handle` → `Multipart.process` → `#handleField`. A **multipart field name**
  is used verbatim as a lodash assignment path.

## Versions (real published npm bytes, installed side-by-side via npm aliases)

| Profile | Version | Storage / guard | Direct `__proto__.x` | Nested `user.__proto__.x` |
|---|---|---|---|---|
| v0 | 10.1.2 | `#fields = {}` (plain) | **pollutes** | **pollutes** |
| v1 | 10.1.4 | `#fields = Object.create(null)` (CVE-2026-25754 fix) | blocked | **pollutes (bypass)** |
| v2 | 10.1.5 | `add()` drops keys whose `lodash.toPath` has `__proto__`/`prototype`/`constructor` | blocked | blocked |

## Why the fix is incomplete
`Object.create(null)` only removes the prototype of the *root* storage object. The field name is
still an attacker-controlled `lodash.set` path, and lodash creates any missing intermediate container
as a plain `{}`. `user.__proto__.pcbPolluted` therefore builds a normal object at `user`, whose
`__proto__` **is** `Object.prototype` — reopening the pollution. GHSA-qcm7-3vpr-hj5h:
*"payloads containing a non-dangerous segment before `__proto__` … such as `user.__proto__.polluted`,
still lead to Object.prototype pollution."* V2 closes it with a per-segment key sanitizer in `add()`.

## Harness (real-library-wrap)
`service.mjs` drives the **real** `BodyParserMiddleware.handle` over a genuine `multipart/form-data`
POST (`@adonisjs/http-server` `RequestFactory`/`HttpContextFactory` only wrap the real Node req/res —
the parse is 100% real bodyparser). Because prototype pollution is process-global, **each `/probe`
runs in a fresh forked worker** (`worker.mjs`) that replays the received bytes through the real
parser and reports only `({}).pcbPolluted` (a fresh empty object's inherited canary). The flag is the
field **value**; it surfaces as `canary_value` iff `Object.prototype` was polluted.

## Run the gate
```bash
python3 oracle.py --run-gate      # builds v0/v1/v2, gates, tears down
```
Result: `passed=true` (original pollutes@v0 / blocked@v1 ; residual pollutes@v1 / blocked@v2 ;
original also blocked@v2). See `repro.log`.

分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。
