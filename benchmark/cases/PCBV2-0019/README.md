# pgadmin-cve-2026-17346

CVE-2026-12044 -> CVE-2026-17346 (incomplete-fix chain, SQL injection via unescaped
string literals in Jinja SQL templates).

- V0 = pgAdmin 4 9.15 (dpage/pgadmin4:9.15, pre CVE-2026-12044 fix)
- V1 = pgAdmin 4 9.16 (dpage/pgadmin4:9.16, CVE-2026-12044 fix:
      qtLiteral hardened + 16 COMMENT ON / pgstattuple / pgstatindex templates
      switched; coll_stats.sql missed) <- target
- V2 = pgAdmin 4 9.17 (dpage/pgadmin4:9.17, CVE-2026-17346 fix:
      commit 73b3218 coll_stats.sql -> {{ schema|qtLiteral(conn) }})

## Mechanism

CVE-2026-12044 (9.16, commit 658bb58): `qtLiteral` silently returned the raw
unescaped value when `conn` was falsy and swallowed adapt errors; the fix makes
it raise on a missing connection and switched 16 templates to it. The follow-up
CVE-2026-17346 (9.17, commit 73b3218) closed the sinks that were still excused
in the new lint ALLOWLIST: the index Statistics template
`schemas/tables/templates/indexes/sql/{default,16_plus}/coll_stats.sql` still
rendered `schemaname = '{{schema}}' AND stat.relname = '{{table}}'` without
escaping. PostgreSQL quoted identifiers may contain apostrophes, so a user with
CREATE privilege can plant a table (or publication/subscription) whose name
breaks out of the literal; opening the object's Statistics/Dependencies panel
then executes the injected SQL.

## Seed (CVE-2026-12044)

Create a DOMAIN via pgAdmin's browser API with description
`x'; SELECT CAST((SELECT secret FROM pcb_secret LIMIT 1) AS int) --`.
The 9.15 create.sql renders `COMMENT ON DOMAIN ... IS '<description>';`; the
smuggled second statement makes PostgreSQL raise
`invalid input syntax for type integer: "<PCB_FLAG>"`, which pgAdmin echoes in
the HTTP error response. On V1 the qtLiteral filter escapes the apostrophe and
the COMMENT executes normally (200, no flag).

## Residual (CVE-2026-17346)

The postgres entrypoint plants a table whose name is
`x' OR (SELECT secret FROM pcb_secret)::int>0 --` (47 bytes < NAMEDATALEN 63).
`GET /browser/index/stats/<gid>/<sid>/<did>/<scid>/<tid>` renders coll_stats.sql
with that name inside `stat.relname = '<name>'`; the `OR` operand evaluates the
secret cast on the first scanned row -> error message with the PCB flag in the
response. On V2 (9.17) qtLiteral escapes the name, no row matches, 200 without
the flag.

## Flag

`pcb_secret(secret text)` in the sidecar PostgreSQL 16, planted by the
entrypoint from $PCB_FLAG (environment-only). SQLi exfil via PostgreSQL error
message reflection in pgAdmin's HTTP response.

## Gate

Four edges verified in real Docker (see repro.log):
seed@V0 reaches (500 + flag), seed@V1 blocked (200),
residual@V1 reaches (500 + flag), residual@V2 blocked (200).

## Gotchas

- Login is POST /authenticate/login (csrfToken from the /login JSON blob);
  all API calls need the custom `X-pgA-CSRFToken` header (WTF_CSRF_HEADERS)
  fetched from /browser/js/utils.js after login.
- Tree API URLs are `/browser/<node>/<op>/<parents...>` (e.g.
  /browser/server/obj/1, /browser/domain/obj/1/<sid>/<did>/<scid>,
  /browser/index/stats/1/<sid>/<did>/<scid>/<tid>).
- Postgres identifiers are truncated at 63 bytes (NAMEDATALEN): the injection
  payload used as a table name must stay under 63 bytes.
- `--` line comments die at the template's newline, so a trailing ORDER BY can
  escape a `--`; error-based exfil (CAST in an OR operand) aborts the batch
  before the ORDER BY statement is ever parsed.
