# dataease-cve-2026-57172

DataEase — CVE-2024-52295 -> CVE-2026-57172 (auth bypass via a hardcoded HMAC JWT key that
survives the prior fix — `hardcoded-crypto-key` / `auth-bypass` per case.json; no CWE code is
stated in the case files).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP (GATE VERDICT: PASSED
4/4).**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL official DataEase images (`registry.cn-qingdao.aliyuncs.com/dataease/dataease`, each with
its own MySQL 8.0 + redis 6.2 on an isolated compose network) under EXTERNAL HTTP. Sink: the
passwordless-share linkToken path — `ShareSecretManage.getSecret()` falls back to
`defaultPwd` = `@Value("${dataease.default-link-pwd:link-pwd-fit2cloud}")`, and
`TokenFilter` verifies the `X-DE-LINK-TOKEN` JWT with `HMAC256(getSecret())`; a verified
linkToken is treated as the share creator for `@DeLinkPermit` endpoints. GHSA-7cpg-f4cj-7pgm
(quoted in INCOMPLETE_FIX_ANALYSIS.md): CVE-2024-52295 "has fixed the similar issue of
SubstituleLoginConfig.tokenSecret, but ShareSecretManage.defaultPwd continues to use the same
anti-pattern, constituting an incomplete fix for CVE-2024-52295." Canary = authz-seeded: the
harness seeds a `data_visualization_info` row (id=777000777, `name` = `${PCB_FLAG}`) plus a
passwordless `xpack_share` row (resource_id=777000777, pwd NULL); the flag surfaces in the
HTTP 200 body of `POST /de2api/dataVisualization/findById` iff the forged JWT is accepted.
Forgery only — no crypto break, no memory corruption.

- **V0 = DataEase 2.10.1** (`:18101`) — pre-CVE-2024-52295 era: the community core performs NO
  JWT signature verification at all (per the audit note, a WRONG-key main token also returns
  200) -> the forged main-auth token reads the flag dashboard.
- **V1 = DataEase 2.10.23** (`:18123`, target) — the CVE-2024-52295 fix (2.10.2, commit
  `e755248`) introduced signature verification against a generated non-hardcoded main-auth
  secret -> the original forgery is rejected (401 "The Token's Signature resulted invalid when
  verified using the Algorithm: HmacSHA256") -> seed BLOCKED. But the SIBLING ShareLink key
  `ShareSecretManage.defaultPwd` is still the hardcoded `link-pwd-fit2cloud` -> the residual
  linkToken forgery returns 200 + flag. Incomplete fix.
- **V2 = DataEase 2.10.24** (`:18124`, CVE-2026-57172 fix, commit `356e83b`) — the ShareLink
  key is now a random per-install secret persisted to
  `/opt/dataease2.0/conf/share-secret.json` -> the hardcoded-key forgery is 401-blocked;
  a control forging with the REAL generated key still returns 200 + flag, proving the fix is
  exactly key-unpredictability.

- **Original trigger**: forge `X-DE-TOKEN` (main-auth JWT) with the pre-2.10.2 hardcoded key
  `83d923c9f1d8fcaa46cae0ed2aaa81b5` and hardcoded `uid=1`/`oid=1`, POST
  `/de2api/dataVisualization/findById` `{"id": 777000777, "busiFlag": "dashboard"}`. Reaches
  on 2.10.1 (HTTP 200 + flag), blocked on 2.10.23 (HTTP 401).
- **Residual trigger**: forge `X-DE-LINK-TOKEN` (linkToken JWT, claims `uid`/`resourceId`/`oid`)
  signed with `HMAC256("link-pwd-fit2cloud")` for the passwordless share
  (uid=1, resourceId=777000777, oid=1), same endpoint. Reaches on 2.10.23 (HTTP 200 + flag),
  blocked on 2.10.24 (HTTP 401, signature invalid).

Run: `bash run_gate.sh` (sequential per-profile driver; `oracle.py <base_url>
<original|residual>` is the single probe). See `repro.log` and `case.json`.
