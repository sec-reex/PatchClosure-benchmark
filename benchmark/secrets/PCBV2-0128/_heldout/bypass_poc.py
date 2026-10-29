#!/usr/bin/env python3
"""[HELD-OUT] CVE-2017-15095 residual for jackson-databind-cve-2017-15095 -- REAL jackson-databind behind a REAL
HTTP REST service, driven over external HTTP.

CVE-2017-7525's fix added a class BLACKLIST (BeanDeserializerFactory.checkIllegalTypes /
DEFAULT_NO_DESER_CLASS_NAMES, databind#1599, in 2.8.9) to jackson-databind's default-typing deserialization.
That blacklist blocks the seed's class name -- but it is an INCOMPLETE List of Disallowed Inputs (CWE-184): it
enumerates only a handful of known gadget names, so any dangerous class whose name is NOT in the set still
deserializes. The advisory (CVE-2017-15095, NVD): "This issue extends the previous flaw CVE-2017-7525 by
blacklisting more classes that could be used maliciously" (fixed in 2.8.10 / 2.9.1; databind#1680 and #1737).

Confirmed against the V1 (2.8.9) blacklist: DEFAULT_NO_DESER_CLASS_NAMES contains the #1599 set only
(commons-collections, groovy, spring ObjectFactory, xalan TemplatesImpl). It does NOT contain
`com.mchange.v2.c3p0.WrapperConnectionPoolDataSource`, one of the additional c3p0 gadget names the
CVE-2017-15095 fix adds in 2.8.10 (databind#1737). So the residual POSTs the SAME kind of benign default-typing
JSON body to the SAME real endpoint (POST /deser) but naming that off-2.8.9-blacklist class:

    ["com.mchange.v2.c3p0.WrapperConnectionPoolDataSource", {}]

  * V1 = 2.8.9 (CVE-2017-7525 patched): the name is NOT in DEFAULT_NO_DESER_CLASS_NAMES -> checkIllegalTypes()
    PERMITS it -> readValue() instantiates the benign shadow bean -> its ctor reads /canary/flag.txt -> flag
    echoed (RESIDUAL REACHES on V1, past the 7525 fix -- the enumerated blacklist is incomplete).
  * V2 = 2.8.10 (CVE-2017-15095 patched): the name is now in DEFAULT_NO_DESER_CLASS_NAMES (databind#1737) ->
    checkIllegalTypes() throws "Illegal type ... prevented for security reasons" BEFORE construction -> no flag
    (BLOCKED). This blacklist extension is exactly the CVE-2017-15095 remediation that superseded the narrow
    -7525 enumeration.

Same sink (the running service's REAL jackson default-typing readValue() -> createBeanDeserializer ->
checkIllegalTypes() blacklist, loaded from the pinned jar) and same canary channel (the service echoes the
CanaryHolder token once a shadow bean is instantiated past the filter) as the seed; only the probe class NAME
moves from an on-2.8.9-blacklist name to the residual off-blacklist name. BENIGN: the request body carries only
the class NAME + an empty object; no gadget chain, no JNDI/RMI, no command execution.
"""
from __future__ import annotations

RESIDUAL_PROBE = "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"
# Default-typing polymorphic JSON body naming the residual c3p0 class.
RESIDUAL_JSON = '["' + RESIDUAL_PROBE + '", {}]'

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["c3p0_name_not_on_7525_blacklist"]


def candidate(vector: str = "c3p0_name_not_on_7525_blacklist"):
    return {
        "id": "cve-2017-15095-" + vector,
        "probe_class": RESIDUAL_PROBE,   # c3p0 gadget FQCN added only by #1737 in 2.8.10
        "json_body": RESIDUAL_JSON,
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
