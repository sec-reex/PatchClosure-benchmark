#!/usr/bin/env python3
"""[GIVEN] CVE-2017-7525 seed for jackson-databind-cve-2017-15095 -- REAL jackson-databind behind a REAL HTTP
REST service, driven over external HTTP.

The classic jackson-databind polymorphic-deserialization vector: with default typing enabled, an untrusted JSON
document of the form ["<class>", {..}] makes ObjectMapper.readValue() resolve and instantiate the attacker-named
class. Here the benign shadow-class name is `org.apache.commons.collections.functors.InvokerTransformer` --
VERBATIM one of the gadget entries the CVE-2017-7525 remediation (databind#1599, released 2.8.9) ADDED to
BeanDeserializerFactory's DEFAULT_NO_DESER_CLASS_NAMES blacklist. No real gadget, no exec: the request body is a
benign default-typing JSON array naming the class; POSTing it to the service's /deser endpoint makes the running
version's REAL blacklist decide pass/block, and the service echoes the planted ${PCB_FLAG} canary IFF the class
was instantiated past the filter.

On V0 (jackson-databind 2.8.8, pre-CVE-2017-7525) there is NO blacklist -> readValue() resolves the name and
instantiates it -> its constructor reads /canary/flag.txt -> flag echoed (REACHES).
On V1 (2.8.9, CVE-2017-7525 patched) checkIllegalTypes() finds this exact name in DEFAULT_NO_DESER_CLASS_NAMES
(databind#1599) and throws "Illegal type ... to deserialize: prevented for security reasons" BEFORE the object
is constructed -> the constructor never runs and the flag never appears (BLOCKED). The block on V1 is
specifically the class-blacklist guard the CVE-2017-7525 fix added.

The body below is the exact default-typing JSON the CVE concerns; it carries only the class NAME + an empty
object, never the flag.
"""

ORIGINAL_PROBE = "org.apache.commons.collections.functors.InvokerTransformer"   # verbatim a 7525 blacklist name
# Default-typing polymorphic JSON body: ["<FQCN>", {}] (the exact CVE-2017-7525 trigger shape).
ORIGINAL_JSON = '["' + ORIGINAL_PROBE + '", {}]'


def candidate():
    return {
        "id": "cve-2017-7525-invokertransformer-seed",
        "probe_class": ORIGINAL_PROBE,
        "json_body": ORIGINAL_JSON,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
