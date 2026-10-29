# fast-jwt-cve-2026-34950

fast-jwt (nearform) — CVE-2023-48223 -> CVE-2026-34950 (JWT public-key-vs-HMAC key classification /
algorithm confusion, CWE-347).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Node/Express HTTP service (`server.js`, `node:20-slim`, npm-pinned `fast-jwt` + `express@4.19.2`)
exposes `GET /admin` and `GET /admin-tainted` (Bearer JWT). Both routes verify via the REAL, unmodified
published `createVerifier` configured with the server's RSA PUBLIC key and NO explicit `algorithms`
restriction, so the allowed algorithms are DERIVED from the key via
`detectPublicKeyAlgorithms` -> `performDetectPublicKeyAlgorithms` in `src/crypto.js`. Same sink, same
fix mechanism (`publicKeyPemMatcher`); the bypass advisory GHSA-mvf2-f6gm-w987 is literally titled
"Incomplete fix for CVE-2023-48223".

- **V0 = fast-jwt 3.3.1** (`:18230`) — `publicKeyPemMatcher` is the plain string
  `'-----BEGIN PUBLIC KEY-----'` used with `.includes()`; a PKCS1 header
  `-----BEGIN RSA PUBLIC KEY-----` is NOT matched -> the public key is misclassified as an HMAC
  secret -> the -48223 seed reaches the flag.
- **V1 = fast-jwt 3.3.2** (`:18231`, target) — fix commit `15a6e92` swaps `.includes()` for the regex
  `/^-----BEGIN( RSA)? PUBLIC KEY-----/` -> the clean-key seed is BLOCKED (reclassified away from
  HMAC), but the regex is `^`-anchored and the public-key path does NOT `.trim()` (the private-key
  path does: `key.trim().match(...)`) -> a LEADING newline defeats the match -> the CVE-2026-34950
  residual still reaches the flag. Incomplete fix.
- **V2 = fast-jwt 6.2.0** (`:18232`, -34950 fix) — `performDetectPublicKeyAlgorithms` does
  `const trimmedKey = key.trim()` before matching (and maps a PKCS1 header to `rsaAlgorithms`
  directly) -> residual BLOCKED.

Flag channel: the server publishes its PKCS1 public key at `GET /pubkey` (public knowledge); the
attacker forges an HS256 token whose HMAC secret is the public-key string itself with payload
`{"sub":"attacker","role":"admin"}`, and the admin route echoes `PCB_FLAG` (compose env, not app code)
in the JSON response only when the forged token verifies AND `payload.role === 'admin'`. No gadget
chain, no command execution. Original uses `/admin` (verifier key = clean `PUB`); residual uses
`/admin-tainted` (verifier key = `"\n" + PUB` — the GHSA's database-retrieved-key deployment).

- **Original trigger**: HS256 with `secret = PUB` (clean PKCS1 PEM, no leading whitespace) -> `/admin`;
  flag on 3.3.1 (200), blocked on 3.3.2 (401 `Unsupported PEM public key.`) and on 6.2.0.
- **Residual trigger**: HS256 with `secret = ("\n" + PUB).encode()` — one LEADING newline defeats the
  `^` anchor -> `/admin-tainted`; flag on 3.3.2 (200, RESIDUAL), blocked on 6.2.0 (401
  `The token algorithm is invalid.`).

Run: `python3 gate.py` (compose services up + `PCB_FLAG` set; see `scripts/start.sh`). See `repro.log`
and `case.json`.

> NOTE: `patch_real.diff` is a binary diff of `.git/index` (git index internals), not a readable
> source patch of `src/crypto.js`; the actual guard evolution is documented in `patch.diff` and
> INCOMPLETE_FIX_ANALYSIS.md.
> NOTE: the `poc/original_poc.py` docstring says "blocked on V1 (fast-jwt 5.x ...)" but V1 is
> fast-jwt 3.3.2 per case.json/docker-compose — stale version inside that comment.
