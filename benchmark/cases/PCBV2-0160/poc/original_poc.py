#!/usr/bin/env python3
"""[GIVEN] CVE-2022-1292 seed exploit for the REAL OpenSSL c_rehash.

The seed is a certificate FILE NAME carrying a shell command-substitution payload.
On V0 (real OpenSSL 1.1.1n) link_hash_cert builds a backtick shell command
    `"$openssl" x509 $x509hash -fingerprint -noout -in "$fname"`
with $fname interpolated inside double quotes (only `"` escaped), so `$(...)` in the
name is executed by the shell.  On V1 (real 1.1.1o) that call site was converted to a
list-form compute_hash() (open($fh,"-|",@_), no shell) -> the seed is BLOCKED.

The trigger is a REAL external invocation of the REAL c_rehash binary on a directory
containing the malicious-named file (see entrypoint.sh).  The payload is BENIGN: it only
echoes the planted ${PCB_FLAG} into a relative file.
"""
from __future__ import annotations


def candidate() -> dict:
    # flavor selects the malicious filename the container seeds (see entrypoint.sh).
    return {"probe_id": "cve-2022-1292-original", "flavor": "original"}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
