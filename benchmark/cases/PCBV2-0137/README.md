# librechat-cve-2026-54037

CVE-2025-7105 -> CVE-2026-54037 (incomplete-fix chain, conversation-clone rate-limit DoS family).

- V0 = LibreChat v0.7.8 (no fork/duplicate rate limiting)
- V1 = LibreChat v0.7.9 (CVE-2025-7105 fix `97a99985`: `/api/convos/fork`
  throttled with forkIpLimiter/forkUserLimiter; `/api/convos/duplicate`
  MISSED) <- target
- V2 = LibreChat v0.8.4-rc1 (CVE-2026-54037 fix: same limiters applied to
  `/api/convos/duplicate`)

## Seed (CVE-2025-7105)

An authenticated user floods `POST /api/convos/fork`. On v0.7.8 there is no
rate limiting -> every request is processed (0x HTTP 429). On v0.7.9 the fix
(PR #8269) added `api/server/middleware/limiters/forkLimiters.js` to the `/fork`
route -> after `FORK_USER_MAX` (3, env-set) requests the server answers
`429 Too many conversation fork requests`.

## Residual (CVE-2026-54037)

The 0.7.9 fix throttled only `/fork`. Its sibling "clone" operation
`POST /api/convos/duplicate` (`duplicateConversation` in
`utils/import/fork.js` — the same expensive clone work) received no limiter
from 0.7.9 through 0.8.3. Flooding `/duplicate` on V1 (0.7.9) yields 0x 429;
on V2 (0.8.4-rc1) the same forkIpLimiter/forkUserLimiter instances are applied
to `/duplicate` -> >=1x 429.

## Gate

DoS-threshold variant (no planted flag token): four edges verified in real
Docker with the official images and real MongoDB. Each edge = 60 authenticated
POSTs; "reaches" = 0x HTTP 429, "blocked" = >=1x HTTP 429.

| edge | probe | result |
|---|---|---|
| seed@V0 | 60x fork | 0x 429 (reaches) |
| seed@V1 | 60x fork | >=1x 429 (blocked) |
| residual@V1 | 60x duplicate | 0x 429 (reaches) |
| residual@V2 | 60x duplicate | >=1x 429 (blocked) |

See repro.log. Env: `FORK_USER_MAX=3`, `FORK_IP_MAX=10` on V1/V2; `PCB_FLAG`
accepted but unused (threshold case).
