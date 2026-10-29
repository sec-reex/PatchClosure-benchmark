#!/usr/bin/env python3
"""[GIVEN] CVE-2023-49070 seed -- the pre-auth XML-RPC deserialization sink, observed
over the REAL Apache OFBiz control endpoint.

Its own channel is the OFBiz request-map `xmlrpc` (uri /webtools/control/xmlrpc). The
CVE-2023-49070 fix (V1 = 18.12.10, commit c59336f604 "Remove xml rpc") DELETED that
request-map from webtools' controller.xml. We do NOT perform any deserialization --
benign benchmark canary. The probe only observes whether the request-map still exists:

  * V0 = pre-49070 -> the `xmlrpc` request-map resolves; OFBiz routes to the XmlRpc
                      event handler (endpoint LIVE). The response is NOT the
                      "Unknown request" controller error.  SEED REACHABLE.
  * V1 = 18.12.10  -> the request-map is gone; OFBiz's RequestHandler raises
                      "Unknown request [xmlrpc]" and renders the default error page.
                      SEED CLOSED on V1 (on its own channel).

We send the auth-bypass params too so that on V0 the request actually reaches the
handler (the removed-request check in RequestHandler.doRequest happens before the
security check, so on V1 it is "Unknown request" regardless of params).

Because the seed sink is REMOVED on V1 while the residual (CVE-2023-51467 auth bypass)
uses a DIFFERENT sink (the LoginWorker login predicate), this is a Variant-B
sibling-sink case: the seed cannot share the residual's flag channel.
"""
from __future__ import annotations

SEED_PATH = "/webtools/control/xmlrpc"
# Marker that appears in OFBiz's controller error page iff the request-map was removed.
SEED_CLOSED_MARKER = "Unknown request"


def candidate() -> dict:
    return {
        "id": "cve-2023-49070-xmlrpc-endpoint",
        "path": SEED_PATH,
        "method": "GET",
        "query": "USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
