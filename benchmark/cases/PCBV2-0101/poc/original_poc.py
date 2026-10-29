#!/usr/bin/env python3
"""[GIVEN] CVE-2019-9212 seed for deser_sofahessian_blacklist -- REAL sofa-hessian behind a REAL HTTP service.

The classic SOFA Hessian deserialization vector: an untrusted Hessian2 stream naming a class that the
deserializer resolves through its class-name BLACKLIST. Here the benign shadow-class name is
`com.caucho.naming.Qname` -- VERBATIM one of the two Resin-gadget entries the CVE-2019-9212 remediation ADDED
to security/serialize.blacklist on the 3.x line. No real gadget, no exec: the request body is a benign Hessian2
typed map naming the class (see attacker/StreamGen.java); POSTing it to the service's /deser endpoint makes the
running version's REAL blacklist decide pass/block, and the service echoes the planted ${PCB_FLAG} canary IFF
the name passed the filter.

On V0 (sofa-hessian 3.3.13, pre-CVE-2019-9212) the blacklist has NO com.caucho.naming entry -> the class name
PASSES -> deserialization proceeds -> the service reads /canary/flag.txt -> flag echoed (REACHES).
On V1 (3.5.4, CVE-2019-9212 patched) security/serialize.blacklist contains the prefix `com.caucho.naming.Qname`
-> NameBlackListFilter.resolve() throws "Class com.caucho.naming.Qname is in blacklist." before the object is
decoded -> flag never appears (BLOCKED). The block on V1 is specifically the CVE-2019-9212 blacklist addition.
(NB: matching is case-sensitive startsWith, and the 3.x fix entry is the lowercase `Qname`; the seed uses that
exact string so the guard genuinely fires on V1.)

The payload below is the exact REAL Hessian2Output encoding of the benign typed map {"probe": <fqcn>} for the
class name (wire-format-stable across 3.3.13/3.5.4/3.5.5); it carries only the class NAME + a 2-string map,
never the flag.
"""

ORIGINAL_PROBE = "com.caucho.naming.Qname"   # verbatim the 9212 blacklist entry (Resin QName gadget name)
# REAL Hessian2 typed-map stream for the class above (from attacker/StreamGen.java run against sofa-hessian).
ORIGINAL_HEX = (
    "4D740017636F6D2E63617563686F2E6E616D696E672E516E616D65"
    "0570726F626517636F6D2E63617563686F2E6E616D696E672E516E616D657A"
)


def candidate():
    return {
        "id": "cve-2019-9212-caucho-qname-seed",
        "probe_class": ORIGINAL_PROBE,
        "payload_hex": ORIGINAL_HEX,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
