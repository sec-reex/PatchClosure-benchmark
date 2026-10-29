#!/usr/bin/env python3
"""[HELD-OUT] CVE-2009-4898 residual exploit for twiki-cve-2009-4898.

CVE-2009-4898 is the documented INSUFFICIENT-FIX bypass of CVE-2009-1339: the
TWiki 4.3.1 fix only forced /bin/save to POST, so an attacker page can still auto-
submit a cross-site **POST** form to the real save script (the CVE demo: the save
URL in a FORM ACTION plus a submit() in the BODY onload). That forged POST rides
the victim admin's TWIKISID cookie but carries NO valid crypt token (it cannot --
the one-time token lives only in the victim's same-origin edit-form DOM). On V1
(TWiki 4.3.1) the POST-only guard accepts it -> the privileged save runs and the
page surfaces the admin-only flag. On V2 (TWiki 4.3.2) verifyCryptToken rejects the
missing token (invalidtoken) -> blocked.

The oracle drives the request shape (mode); the harness supplies the fixed
privileged-save payload that surfaces the admin-only flag on the victim's own view.
"""


def candidate():
    return {
        "probe_id": "cve-2009-4898-residual",
        "mode": "residual",     # forged POST /bin/save, no valid crypt token
    }


if __name__ == "__main__":
    print(candidate())
