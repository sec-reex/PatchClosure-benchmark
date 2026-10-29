#!/usr/bin/env python3
"""[HELD-OUT] CVE-2017-17485 residual for jackson-databind-cve-2017-17485 -- REAL jackson-databind behind a REAL
HTTP REST service, driven over external HTTP.

CVE-2017-7525's fix added a class BLACKLIST (BeanDeserializerFactory.checkIllegalTypes /
DEFAULT_NO_DESER_CLASS_NAMES, databind#1599), later extended by CVE-2017-15095 (#1680/#1737), to
jackson-databind's default-typing deserialization. That guard is an EXACT fully-qualified-name set (CWE-184: an
incomplete List of Disallowed Inputs), so any dangerous class whose name is NOT enumerated still deserializes.
The advisory (CVE-2017-17485, NVD): jackson-databind "through 2.8.10 and 2.9.x through 2.9.3 allows
unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw ...
bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath" (fixed in
2.7.9.2 / 2.8.11 / 2.9.4; databind#1855).

Confirmed against the V1 (2.9.3) guard: DEFAULT_NO_DESER_CLASS_NAMES enumerates the #1599 + #1680/#1737 gadget
names but does NOT contain any Spring application-context class, and 2.9.3's checkIllegalTypes() does an
EXACT-name match only (no superclass handling). So the residual POSTs the SAME kind of benign default-typing JSON
body to the SAME real endpoint (POST /deser) but naming the off-2.9.3-blacklist Spring class:

    ["org.springframework.context.support.FileSystemXmlApplicationContext", {}]

  * V1 = 2.9.3 (-7525 + -15095 patched): the name is NOT in the exact-name set and there is no Spring superclass
    handling -> checkIllegalTypes() PERMITS it -> readValue() instantiates the benign shadow bean (which extends
    a benign AbstractApplicationContext) -> its ctor reads /canary/flag.txt -> flag echoed (RESIDUAL REACHES on
    V1, past the -7525/-15095 fix -- the enumerated blacklist is incomplete for Spring).
  * V2 = 2.9.4 (CVE-2017-17485 patched): the guard is SubTypeValidator.validateSubType() (databind#1855) which,
    for any concrete "org.springframework." class, walks the superclass chain and rejects it when an ancestor's
    SIMPLE name is "AbstractApplicationContext" -> "Illegal type ... prevented for security reasons" BEFORE
    construction -> no flag (BLOCKED). This Spring-specific handling is exactly the CVE-2017-17485 remediation.

Same sink (the running service's REAL jackson default-typing readValue() -> createBeanDeserializer -> version
guard, loaded from the pinned jar) and same canary channel (the service echoes the CanaryHolder token once a
shadow bean is instantiated past the guard) as the seed; only the probe class NAME moves from an on-blacklist
name to the residual Spring name. BENIGN: the request body carries only the class NAME + an empty object; no
gadget chain, no remote XML fetch, no SpEL, no command execution. (ClassPathXmlApplicationContext, the sibling
Spring context name also covered by #1855 via the same AbstractApplicationContext ancestry, is an equivalent
residual vector.)
"""
from __future__ import annotations

RESIDUAL_PROBE = "org.springframework.context.support.FileSystemXmlApplicationContext"
# Default-typing polymorphic JSON body naming the residual Spring application-context class.
RESIDUAL_JSON = '["' + RESIDUAL_PROBE + '", {}]'

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["spring_filesystemxml_appcontext_not_on_2.9.3_blacklist"]


def candidate(vector: str = "spring_filesystemxml_appcontext_not_on_2.9.3_blacklist"):
    return {
        "id": "cve-2017-17485-" + vector,
        "probe_class": RESIDUAL_PROBE,   # Spring app-context FQCN added to the guard only by #1855 in 2.9.4
        "json_body": RESIDUAL_JSON,
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
