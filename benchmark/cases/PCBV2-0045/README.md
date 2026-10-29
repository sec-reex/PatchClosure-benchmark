# INJ-01-superset-denylist

Apache Superset — CVE-2024-39887 -> CVE-2025-55674 (DISALLOWED_SQL_FUNCTIONS denylist bypass via an
inline SQL comment, SQL authorization bypass / CWE-89).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Three REAL official `apache/superset` images (4.0.1 / 4.0.2 / 5.0.0, no Superset source copied; the
only image change is installing `psycopg2-binary` so the app can reach the analytics DB) each boot the
real app with `superset_config.py` turning on the REAL `DISALLOWED_SQL_FUNCTIONS` denylist (verbatim
from Superset's default `config.py`: postgresql `{version, query_to_xml, inet_server_addr,
inet_client_addr}`), plus a shared REAL `postgres:16-alpine` analytics DB whose `pcb_secret` relation
holds `${PCB_FLAG}` (seeded by each container's `bootstrap.py`). Trigger = authenticated external HTTP
to the REAL SQL Lab API as a low-priv user: `POST /api/v1/security/login` (analyst, `provider:db`) ->
`GET /api/v1/security/csrf_token/` -> `POST /api/v1/sqllab/execute/` (Bearer + X-CSRFToken + session
cookie). Sink: `db_engine_specs/base.py::BaseEngineSpec.execute` ->
`sql_parse.check_sql_functions_exist(query, DISALLOWED_SQL_FUNCTIONS['postgresql'], 'postgresql')`.
The oracle reads `${PCB_FLAG}` from the execute API JSON body: the denylisted PostgreSQL
`query_to_xml` runs the inner query `SELECT val FROM pcb_secret` at the engine and returns the flag as
XML (`<val>PCBFLAG_...</val>`) iff the denylist was bypassed; blocked queries return HTTP 500
"SQL statement contains disallowed function(s)" with no flag.

- **V0 = superset 4.0.1** (`:43201`) — no `DISALLOWED_SQL_FUNCTIONS` enforcement at all
  (`check_sql_functions_exist` not defined/called) -> the seed runs and the flag comes back in the XML.
- **V1 = superset 4.0.2** (`:43202`, target) — CVE-2024-39887 fix (PR #28639 / commit `56f0103`):
  sqlparse-based `ParsedQuery.check_functions_exist` only flags `isinstance(token, Function)` nodes,
  and sqlparse groups `Name` + `Parenthesis` into a `Function` only when `(` IMMEDIATELY follows the
  name (`token_next` skips whitespace but NOT comments) -> the direct `query_to_xml(` call is BLOCKED
  (HTTP 500), but `query_to_xml/**/(` tokenizes as Name + Comment + Parenthesis, never becomes a
  `Function` node, and PostgreSQL treats `/**/` as whitespace and runs the call -> the residual still
  executes and the flag reaches the response. Incomplete fix.
- **V2 = superset 5.0.0** (`:43203`, -55674 fix, commit `ce6d0d5963`) — SQL analysis switched to
  sqlglot: `SQLScript.check_functions_present` walks `find_all(Func)` and comments are discarded when
  the AST is built, so the same `/**/` payload is found -> residual BLOCKED (negative control; V2 also
  blocks the original).

- **Original trigger**: `SELECT query_to_xml('SELECT val FROM pcb_secret', true, false, '')` —
  denylisted `query_to_xml` named directly; on 4.0.2 sqlparse groups it as a `Function` with
  `get_name() == "query_to_xml"` and `BaseEngineSpec.execute` raises `DisallowedSQLFunction`.
- **Residual trigger**: `SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')` —
  same sink, same denylisted function, same API; the only difference is the empty block comment
  between the function name and its argument list, which defeats the sqlparse grouping while remaining
  whitespace to PostgreSQL.

Run: `python3 oracle.py --run-gate --with-v2`. See `repro.log` and `case.json`.

> NOTE (patch.diff content): `INCOMPLETE_FIX_ANALYSIS.md` states, and inspection confirms, that the
> in-case `patch.diff` — despite a header claiming "V0 -> V1 fix (upstream), synced from inputs by
> ROUND9 audit" — contains only an unrelated dialect-table line (`"spark": Dialects.SPARK` in
> `superset/sql_parse.py`), NOT the CVE-2024-39887 security increment. The real V0->V1 fix diff
> (`DISALLOWED_SQL_FUNCTIONS` config, `check_sql_functions_exist`, `ParsedQuery.check_functions_exist`,
> `DisallowedSQLFunction`, the `BaseEngineSpec.execute` hook) is in `patch_real.diff`.
