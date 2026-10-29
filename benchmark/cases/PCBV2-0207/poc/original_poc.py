#!/usr/bin/env python3
"""[GIVEN] CVE-2009-1339 seed exploit for twiki-cve-2009-4898.

The original TWiki CSRF: a forged **GET** request to the real /bin/save script,
riding the victim admin's authenticated TWIKISID session cookie (exactly as an
<img src=".../bin/save/Sandbox/Topic?text=...">  would fire in the victim's
browser). On TWiki 4.3.0 (V0) this performs the save. The CVE-2009-1339 fix
(TWiki 4.3.1 = V1) rejects it with `post_method_only`, so this seed is BLOCKED on V1.

The oracle drives the request shape (mode); the harness supplies the fixed
privileged-save payload that surfaces the admin-only flag on the victim's own view.
"""


def candidate():
    return {
        "probe_id": "cve-2009-1339-seed",
        "mode": "seed",       # forged GET /bin/save (no token)
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
