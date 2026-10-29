# pgadmin-cve-2026-17348

CVE-2026-12046 -> CVE-2026-17348 (incomplete-fix chain, unauthenticated reach
of routes missing @pga_login_required).

- V0 = pgAdmin 4 9.15 (dpage/pgadmin4:9.15, pre CVE-2026-12046 fix)
- V1 = pgAdmin 4 9.16 (dpage/pgadmin4:9.16, CVE-2026-12046 fix:
      @pga_login_required added to sqleditor close/update; Constraints
      blueprint routes still undecorated) <- target
- V2 = pgAdmin 4 9.17 (dpage/pgadmin4:9.17, CVE-2026-17348 fix:
      commit 24fdcf0 decorates Constraints nodes/proplist/delete,
      preferences.get_all_cli, debugger.close, schema_diff.close)

## Mechanism

In SERVER mode pgAdmin enforces authentication per route with
@pga_login_required; the before_request hook only handles desktop-mode
auto-login, so a route shipped without the decorator is reachable
unauthenticated (CWE-306). CVE-2026-12046 fixed the SQL Editor
close/update_connection routes (which reach pickle.loads). CVE-2026-17348
closed the same defect class on the Constraints blueprint routes.

## Seed (CVE-2026-12046)

Anonymous request (CSRF token harvested from GET /login, mirroring the
upstream regression test) DELETE /sqleditor/close/424242:
V0 (9.15) -> 200 {"data":{"status":true}} (route body runs with an empty
session). V1 (9.16) -> 302 to /login?next=... (@pga_login_required).

## Residual (CVE-2026-17348)

Anonymous GET /browser/constraints/nodes/1/1/1/1/1/:
V1 (9.16) -> 410 {"errormsg":"Server not found."} (route body runs;
connection_manager() raises ObjectGone for an unauthenticated user).
V2 (9.17) -> 302 to /login?next=... (decorator added).

## Flag

Canary = the auth-gate status class, identical to the signal the upstream
regression test (test_close_requires_auth.py) asserts: BLOCKED = status in
(301, 302, 401, 403); REACHED = the route body response. PCB_FLAG is still
generated/injected per run for traceability.

## Gate

Four edges verified in real Docker (see repro.log):
seed@V0 reaches (200), seed@V1 blocked (302), residual@V1 reaches (410),
residual@V2 blocked (302).

## Gotchas

- pgAdmin's CSRF protection covers GET too (WTF_CSRF_METHODS includes GET)
  and runs BEFORE route decorators, so probes must carry a valid
  X-pgA-CSRFToken even unauthenticated (harvest from GET /login).
- requests follows redirects by default: probes must use
  allow_redirects=False, otherwise the auth redirect to /login is followed
  and the status collapses to 200.
