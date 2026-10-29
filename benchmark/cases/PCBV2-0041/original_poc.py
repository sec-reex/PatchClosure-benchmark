#!/usr/bin/env python3
"""[GIVEN] CVE-2017-18349 seed for deser_fastjson_autotype -- REAL fastjson behind a REAL Java HTTP service, driven
over EXTERNAL HTTP.

The classic fastjson autoType vector: an untrusted JSON object with an "@type" key makes JSON.parse() resolve and
instantiate the named class. Here the benign shadow-bean name is `com.mchange.PcbFlagBean` -- a stand-in occupying
the "com.mchange" prefix that is on fastjson's OWN built-in autoType denyList (no real gadget, no exec). POSTing it
as the JSON body of POST /deser makes the running version's REAL checkAutoType decide pass/block, and the service
echoes the planted ${PCB_FLAG} canary IFF the bean was instantiated past the filter:

    {"@type":"com.mchange.PcbFlagBean","probe":"x"}

On V0 (fastjson 1.2.24, pre-CVE-2017-18349) there is NO checkAutoType/denylist guard -> JSON.parse resolves the name
directly via TypeUtils.loadClass and instantiates it -> its ctor reads /canary/flag.txt -> flag echoed (REACHES).
On V1 (1.2.25, CVE-2017-18349 patched) ParserConfig.checkAutoType() prefix-matches "com.mchange" against the denyList
and throws "autoType is not support ..." BEFORE construction -> the ctor never runs and the flag never appears
(BLOCKED). The block on V1 is specifically the class-denylist guard the CVE-2017-18349 fix added. The body carries
only a class NAME + a trivial field, never the flag.
"""

# Default-typing / autoType JSON body: a bare {"@type":"<FQCN>", ...} object (the exact CVE-2017-18349 trigger shape).
ORIGINAL_JSON = '{"@type":"com.mchange.PcbFlagBean","probe":"x"}'


def candidate():
    return {
        "id": "cve-2017-18349-autotype-literal-seed",
        "probe_class": "com.mchange.PcbFlagBean",   # verbatim under the 1.2.25 denyList prefix "com.mchange"
        "json_body": ORIGINAL_JSON,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
