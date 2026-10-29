#!/usr/bin/env python3
"""[HELD-OUT] CVE-2022-2068 residual exploit for the REAL OpenSSL c_rehash.

The 1.1.1o fix for CVE-2022-1292 hardened only the hash-computation exec path
(link_hash_cert/link_hash_crl).  It MISSED a distinct shell sink: check_file() still
probed each candidate file with a Perl 2-argument open:
    open IN, $fname;
A 2-arg open whose string ends in `|` runs the leading text as a shell command
(/bin/sh -c "<cmd>").  So a file NAMED `a.pem;echo $PCB_FLAG>resid_out|` executes the
injected command on V1 (real 1.1.1o) -- the seed's call site is closed there, but this one
is not.  CVE-2022-2068 (real 1.1.1p) changed check_file to 3-arg open(my $in,"<",$fname),
which opens the literal path (no command) -> BLOCKED on V2.

Trigger = REAL external invocation of the REAL c_rehash on the malicious directory.
The payload is BENIGN: it only echoes the planted ${PCB_FLAG} into a relative file.
"""
from __future__ import annotations


def candidate() -> dict:
    return {"probe_id": "cve-2022-2068-residual", "flavor": "residual"}
