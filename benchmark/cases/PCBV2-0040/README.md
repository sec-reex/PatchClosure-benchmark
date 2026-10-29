# superset-cve-2026-23980

Apache Superset — CVE-2025-48912 -> CVE-2026-23980 (SQLi via adhoc `sqlExpression` —
function-denylist bypass with a double-quoted identifier, CWE-89).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL Apache Superset (official `apache/superset` images) + `postgres:15-alpine` +
`redis:7-alpine`, brought up per profile by `docker-compose.yml`; `bootstrap.sh` runs
`superset db upgrade`, creates the admin user, `superset init`, then starts gunicorn on
container port 8088. The chart-data API `POST /api/v1/chart/data` validates adhoc
`sqlExpression` values against `DISALLOWED_SQL_FUNCTIONS[engine]` (sqlparse token matching) and
then executes the SQL on Postgres. The canary lives in a postgres table `canary` (created by
`init-db.sh` from `${PCB_FLAG}`) that the legitimate dataset (`public_data`) never queries — it
is only reachable through PostgreSQL XML functions that execute SQL/table arguments, whose XML
output comes back in the chart-data API response body.

- **V0 = apache/superset:4.0.2** (`:38400`) — the postgresql deny list (introduced for
  CVE-2024-39887) blocks `query_to_xml` but NOT `table_to_xml`/`database_to_xml`/
  `query_to_xml_and_xmlschema` -> the `table_to_xml('canary', ...)` seed dumps the canary as
  XML and the flag reaches the API response.
- **V1 = apache/superset:4.1.2** (`:38410`, target) — CVE-2025-48912 fix expands the
  DISALLOWED_SQL_FUNCTIONS deny list (`table_to_xml`, `query_to_xml_and_xmlschema`, ...) -> the
  seed is BLOCKED with "SQL statement contains disallowed function(s)". But the deny-list check
  matches sqlparse `Function.get_name().lower()` tokens and does NOT handle PostgreSQL
  double-quoted identifiers -> `"query_to_xml"(...)` fails the string match while Postgres still
  resolves it as the same built-in -> the CVE-2026-23980 residual still reads the canary.
  Incomplete fix.
- **V2 = apache/superset:6.0.0** (`:38420`, -23980 fix) — SQL expressions run through sqlglot
  normalization, which uppercases quoted identifiers; Postgres cannot resolve the uppercased
  `QUERY_TO_XML` -> residual BLOCKED.

Flag channel: `PCB_FLAG` is planted in `canary.flag` by the postgres init script from the
`${PCB_FLAG}` env var; no app code or data is touched. Detector = flag-token substring in the
chart-data API response body (XML-encoded inside `table_to_xml`/`query_to_xml` output). Read-exfil
canary only — no RCE, no shell.

- **Original trigger**: `sqlExpression = CAST(table_to_xml('canary', true, false, '') AS TEXT)`
  — `table_to_xml` is off the 4.0.2 deny list (added to the deny list in 4.1.2); it converts the
  whole `canary` table to XML, bypassing the subquery parser (`has_table_query` sees no `FROM`).
- **Residual trigger**: `sqlExpression = CAST("query_to_xml"('SELECT flag FROM canary LIMIT 1',
  true,false,'') AS TEXT)` — the function name is wrapped in PostgreSQL double quotes so the
  sqlparse token no longer matches the deny list entry, while Postgres folds the quoted
  identifier to the same lowercase built-in; the argument SQL executes and returns the flag.
  Blocked on V2 where sqlglot uppercases the quoted identifier.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.

> NOTE: `case.json` (`oracle.checks.residual_v2_blocked: true`, and the audit evidence text)
> claims the residual was verified BLOCKED on V2 (6.0.0), but `repro.log` (31 lines) contains
> only the V0/V1 gate records — no V2 probe output and no `bypass_blocked_on_v2` check. The V2
> negative control is asserted but not evidenced in the repro log.
> NOTE: `patch_real.diff` here is the upstream CVE-2025-48912 V0->V1 diff (commit
> `5e7299431d8b03070f54dd5bf3593e8b445da096`), whose code change is
> `superset/connectors/sqla/utils.py::get_virtual_table_metadata` (ParsedQuery -> SQLScript /
> `has_mutation`); it does NOT itself show the `DISALLOWED_SQL_FUNCTIONS` deny-list expansion in
> `superset/config.py` that blocks the seed on V1 (that mechanism is documented in
> INCOMPLETE_FIX_ANALYSIS.md and `case.json`). `patch.diff` and `patch_real.diff` are different
> files (verified with `diff -q`).
