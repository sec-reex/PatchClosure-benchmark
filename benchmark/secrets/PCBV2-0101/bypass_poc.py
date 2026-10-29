#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-46983 residual for deser_sofahessian_blacklist -- REAL sofa-hessian behind a REAL HTTP
service, driven over external HTTP.

CVE-2019-9212's fix extended security/serialize.blacklist with two Resin-gadget names. On the 3.x line the two
entries were added VERBATIM as:
    com.caucho.naming.Qname
    com.sun.org.apache.xpath.internal.objects.Xstring
That list is an INCOMPLETE List of Disallowed Inputs (CWE-184). NameBlackListFilter matches with a
case-sensitive `className.startsWith(prefix)`. The intended XString gadget is
`com.sun.org.apache.xpath.internal.objects.XString` (capital S) -- but the blacklist entry was written
`...Xstring` (lowercase s), so the REAL gadget name never matches it and stays deserializable. More broadly,
sofa-hessian's denylist only enumerated a handful of com.sun.* class names, so a JDK-only gadget chain still
passes. CVE-2024-46983 closes this by REPLACING the narrow enumerations with broad package PREFIXES -- including
`com.sun.` -- in 3.5.5.

This residual POSTs the SAME kind of benign Hessian2 typed-map body to the SAME real endpoint (POST /deser) but
naming the class `com.sun.org.apache.xpath.internal.objects.XString` (the real Resin/JDK XString gadget FQCN),
which embodies the residual flaw:
  * V1 = 3.5.4 (CVE-2019-9212 patched): blacklist entry `com.sun.org.apache.xpath.internal.objects.Xstring`
    (lowercase) does NOT prefix-match the correctly-cased `...XString`, and no other 3.5.4 entry is a prefix of
    it -> resolve() PASSES -> Hessian2 deserialization proceeds -> the service reads /canary/flag.txt -> flag
    echoed (RESIDUAL REACHES on V1, past the 9212 fix).
  * V2 = 3.5.5 (CVE-2024-46983 patched): blacklist now contains the broad prefix `com.sun.` ->
    `com.sun.org.apache.xpath.internal.objects.XString`.startsWith("com.sun.") is true -> resolve() throws
    "is in blacklist" BEFORE decoding -> no flag (BLOCKED). This blacklist broadening is exactly the
    CVE-2024-46983 remediation that superseded the narrow 9212 enumeration.

Same sink (the running service's REAL sofa-hessian ClassNameResolverBuilder.buildDefault() blacklist filter,
loaded from the pinned jar) and same read-exfil channel (the service echoes /canary/flag.txt once decoding gets
past the filter) as the seed; only the probe class NAME moves from the caucho Qname entry to the real XString
gadget name. BENIGN: the request stream carries only the class NAME + a benign 2-string map; no gadget chain,
no JNDI/RMI, no command execution. (The XString name already exists in the JDK's java.xml module; the outcome
is governed purely by the version's name-based blacklist, not by any class we ship.)
"""
from __future__ import annotations

RESIDUAL_PROBE = "com.sun.org.apache.xpath.internal.objects.XString"
# REAL Hessian2 typed-map stream for the class above (from attacker/StreamGen.java run against sofa-hessian).
RESIDUAL_HEX = (
    "4D740031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E67"
    "0570726F6265530031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E677A"
)

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["xstring_case_and_prefix_gap"]


def candidate(vector: str = "xstring_case_and_prefix_gap"):
    return {
        "id": "cve-2024-46983-" + vector,
        "probe_class": RESIDUAL_PROBE,   # real XString gadget FQCN; misses 9212's typo'd/narrow entry
        "payload_hex": RESIDUAL_HEX,
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
