# pp2-json-pointer

jsonpointer (npm `jsonpointer`, janl/node-jsonpointer) — CVE-2020-7709 -> CVE-2021-23820 / CVE-2022-4742 (Prototype-pollution string-only guard, CWE-1321 / CWE-843).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Express HTTP service (`app/server.js`, `node:18-bookworm-slim`, `npm install jsonpointer@<ver> express@4.21.2`)
exposes `POST /set` `{pointer,value}` -> the REAL published `jsonpointer.set({}, pointer, value)` (the
sink; pointer may be an RFC-6901 string OR an array of tokens, both valid inputs to the real library),
and `GET /check` reads a fresh object's inherited `isAdmin` and releases `${PCB_FLAG}` iff
`({}).isAdmin === true` (a default-deny authorization gate flipped open by prototype pollution). Same
sink, same guard mechanism; Snyk SNYK-JS-JSONPOINTER-1577287: "a type confusion vulnerability can lead
to a bypass of CVE-2020-7709 when the pointer components are arrays". Pollution is PROCESS-WIDE, so the
oracle restarts the target container (fresh node process => clean `Object.prototype`) between payloads
and versions.

- **V0 = jsonpointer 4.0.1** (`:39891`) — `setter()` key-walk has NO magic-property guard -> the seed
  pollutes `Object.prototype` and reaches the flag.
- **V1 = jsonpointer 4.1.0** (`:39892`, target) — `setter()` opens with a strict `===` STRING compare of
  the RAW segment, `if (pointer[1] === '__proto__') return obj` (plus the
  `pointer[1] === 'constructor' && pointer[2] === 'prototype'` pair), BEFORE the loop, with NO array-key
  handling in `compilePointer()` -> the string seed is BLOCKED (early-return, no write), but the
  nested-array residual slips the guard (`['__proto__'] === '__proto__'` is FALSE) and `obj[part]`
  coerces the array back to `'__proto__'` (CWE-843 type confusion) -> the CVE-2021-23820 residual still
  pollutes and reaches the flag. Incomplete fix.
- **V2 = jsonpointer 5.0.0** (`:39893`, -23820/-4742 fix) — `compilePointer()` throws on any array
  element that is not string/number ("Invalid JSON pointer. Must be of type string or number.") BEFORE
  any walk, and the magic-name guard moves INTO the `setter()` loop over EVERY segment -> residual
  BLOCKED.

- **Original trigger**: string pointer `"/__proto__/isAdmin"` via `POST /set` — split into
  `['', '__proto__', 'isAdmin']`; on 4.1.0 `pointer[1] === '__proto__'` is TRUE so `setter()`
  early-returns with no write (POST returns `ok` but `GET /check` stays `null`).
- **Residual trigger**: nested-array pointer `["", ["__proto__"], "isAdmin"]` via `POST /set` —
  setter() loops FROM INDEX 1 so the array must land at index 1 (index 0 is a dummy mirroring the
  leading empty split segment; the 2-element form Snyk cites lands the array at the skipped index 0 and
  does NOT pollute — established empirically). `['__proto__'] !== '__proto__'` passes the guard, then
  `obj = obj[part]` ToStrings the array back to `'__proto__'` and the leaf writes `isAdmin = true` onto
  `Object.prototype`.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE (CVE numbering): the dossier disagrees with itself on the bypass CVE. `case.json` (and the
> Dockerfile header / `_heldout/bypass_poc.py`) use CVE-2021-23820 / CVE-2022-4742 (advisory URL
> GHSA-8gh8-hqwg-xf34), while `docker-compose.yml` line 1 and `INCOMPLETE_FIX_ANALYSIS.md` say the
> residual should be CVE-2021-23807 / GHSA-282f-qqgm-c34q, arguing that CVE-2020-7709/CVE-2021-23820 are
> the numbers of the SAME flaw on a different package (manuelstofer `json-pointer`) and that the
> package actually installed here is janl `jsonpointer@4.1.0`. The mechanism/versions in this README
> follow the on-disk sources regardless of the numbering dispute.
