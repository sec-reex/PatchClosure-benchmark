# apache-ofbiz-cve-2023-51467

Apache OFBiz — CVE-2023-49070 -> CVE-2023-51467 (the 49070 fix REMOVES the
pre-auth XML-RPC endpoint but leaves the `LoginWorker` login predicate untouched:
a failed userLogin with `requirePasswordChange=Y` returns
`requirePasswordChange`, not `error`, so `checkLogin()` falls through to
`success` for non-empty invalid credentials; auth bypass, CWE-306). **Genuine
incomplete fix; gate passed on real Docker over EXTERNAL HTTPS.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Apache OFBiz built from source per exact `release18.12` branch commit
(base `eclipse-temurin:8-jdk-jammy`, gradle 5.0-rc-5, seed data in embedded
Derby), exercising the REAL
`org.apache.ofbiz.webapp.control.LoginWorker.checkLogin()` via EXTERNAL HTTPS to
the real ControlServlet (OFBiz redirects resolved auth requests http->https, as
the public PoC does). No OFBiz source is copied or modified; a benign
authz-canary webapp `plugins/pcbcanary` adds one `<security auth="true"/>`
request whose groovy event echoes `${PCB_FLAG}` iff `checkLogin` returns
`success` — pure read of an authenticated-only view, no deserialization, no
state change.

Oracle is Variant B (sibling-sink): the seed's channel (the `xmlrpc` request-map)
is REMOVED by the 49070 fix while the auth-bypass predicate is identical on V0
and V1, so Variant A cannot apply. `patch_real.diff` is the CVE-2023-49070 fix
(commit `c59336f604f503df5b2f7c424fd5e392d5923a27`, "Remove xml rpc (#630)":
request-map deleted, xmlrpc client/server deps dropped). The 51467 fix
(commit `1dcfa071804a`, OFBIZ-12873, V2) changes `login()`'s failure return to
`"error"` (plus `UtilValidate.isEmpty()` null-checks in `d8b097f6717a` /
`f10b42fa3713`). case.json `evidence.incomplete_fix_quote`: "CVE-2023-49070 was
fixed in 18.12.10 by REMOVING the pre-auth XML-RPC deserialization endpoint, but
the underlying authentication bypass was left untouched."

- **V0 = pre-49070** (commit `7935a146…`, http `:18120` / https `:18420`) —
  `GET /webtools/control/xmlrpc` resolves (endpoint LIVE); the auth bypass is
  also present.
- **V1 = 18.12.10** (commit `c59336f6…`, http `:18121` / https `:18421`, target)
  — seed CLOSED on its own channel: `Unknown request [xmlrpc]` (request-map
  removed). But `GET /pcbcanary/control/flag?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y`
  -> userLogin fails, `login()` returns `"requirePasswordChange"`, all three
  `checkLogin` disjuncts false -> `"success"` -> 200 + FLAG. Incomplete fix.
- **V2 = 18.12.11** (commit `1dcfa071…`, http `:18122` / https `:18422`, 51467
  fix) — `login()` returns `"error"` -> login/error page, no flag (repro.log).

- **Original trigger (seed, sibling channel)**: `GET /webtools/control/xmlrpc?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y`
  (`poc/original_poc.py` `SEED_PATH`; observes request-map existence only — no
  deserialization is performed).
- **Residual trigger**: `GET /pcbcanary/control/flag?USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y`
  (non-empty INVALID creds + `requirePasswordChange=Y`; `_heldout/bypass_poc.py`
  `FLAG_PATH`, second vector with `nosuchuser`/`nosuchpass`).

Run: `python3 oracle.py --run-gate` (gate 2026-07-16, flag
`PCBFLAG_a668bd8d5038aff32baa35b6f6ea4605`: residual reaches@v1, blocked@v2, seed
closed@v1; passed=true). See `repro.log` and `case.json`. Positive controls:
no-auth `/pcbcanary/control/flag` -> login page, no flag on v1; the residual also
reaches the flag on v0 (the bypass predates the 49070 fix).

> NOTE: `versions.v1` / `v2` carry release numbers 18.12.10 / 18.12.11, but git
> tags 18.12.06..18.12.11 were never published — the recipe pins `release18.12`
> branch commits (`c59336f6…`, `1dcfa071…`), stated in case.json and repro.log.
> Stale lifted-harness file `OfbizAuthCore.java` is retained per the NO-rm
> policy and no longer used.
